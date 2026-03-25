"""
Certificate Transparency Log monitor — with active path probing.

Streams newly issued TLS certificates from certstream WebSocket feed
(primary) and crt.sh polling (fallback). For each discovered hostname
we now generate a set of sensitive-path probe URLs rather than just
pushing the bare root, so the scanner actively hunts for misconfigs
on every fresh domain instead of only checking the index page.
"""

import asyncio
import json
import logging
import ssl

import aiohttp
import certifi

logger = logging.getLogger("aveli.ct_logs")

# Public certstream-community WebSocket endpoint
CT_STREAM_URL = "wss://certstream.calidog.io/"

# crt.sh JSON API — reliable polling fallback
CRTSH_API = "https://crt.sh/"

# Focus on interesting TLDs / patterns for high-value targets
_HIGH_VALUE_KEYWORDS = {
    "pay", "payment", "wallet", "crypto", "defi", "finance", "bank",
    "exchange", "trading", "invest", "fund", "vault", "secure", "auth",
    "login", "account", "admin", "dashboard", "portal", "api", "staging",
    "dev", "test", "beta", "internal", "vpn", "mail", "smtp",
}

# Sensitive paths probed on every discovered domain.
# Ordered by historical exposure frequency.
_PROBE_PATHS = [
    "/",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-config.php",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/database.yml",
    "/secrets.yml",
    "/credentials.json",
    "/.npmrc",
    "/.aws/credentials",
    "/backup.sql",
    "/dump.sql",
    "/.htpasswd",
    "/phpinfo.php",
    "/adminer.php",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/api/v1/users",
    "/api/users",
    "/debug",
    "/console",
    "/server-status",
    "/id_rsa",
    "/private.key",
]


def _is_interesting(hostname: str) -> bool:
    """Return True if the hostname looks worth scanning."""
    hostname_lower = hostname.lower()
    if hostname_lower.startswith("*.") or hostname_lower in {"localhost", "example.com"}:
        return False
    for kw in _HIGH_VALUE_KEYWORDS:
        if kw in hostname_lower:
            return True
    return False


def _expand_domain(domain: str, max_queue_size: int, queue: asyncio.Queue) -> list[str]:
    """Return probe URLs for a domain, respecting queue capacity."""
    urls = []
    remaining = max_queue_size - queue.qsize()
    for path in _PROBE_PATHS:
        if remaining <= 0:
            break
        urls.append(f"https://{domain}{path}")
        remaining -= 1
    return urls


async def _stream_certstream(
    queue: asyncio.Queue,
    max_queue_size: int,
    interesting_only: bool,
    connected_event: asyncio.Event,
) -> None:
    """Connect to certstream WebSocket and push probe URLs to queue."""
    try:
        import websockets  # type: ignore
    except ImportError:
        logger.warning("websockets not installed; certstream disabled. pip install websockets")
        return

    ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    retry_delay = 2

    while True:
        try:
            logger.info("Connecting to CT log stream: %s", CT_STREAM_URL)
            async with websockets.connect(
                CT_STREAM_URL,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
                ssl=ssl_ctx,
            ) as ws:
                retry_delay = 2
                connected_event.set()
                logger.info("certstream connected — streaming live CT log data")
                async for raw_msg in ws:
                    try:
                        msg = json.loads(raw_msg)
                    except (json.JSONDecodeError, ValueError):
                        continue

                    if msg.get("message_type") != "certificate_update":
                        continue

                    leaf = msg.get("data", {}).get("leaf_cert", {})
                    domains: list[str] = leaf.get("all_domains", [])

                    for domain in domains:
                        domain = domain.strip().lstrip("*.")
                        if not domain:
                            continue
                        if interesting_only and not _is_interesting(domain):
                            continue
                        for url in _expand_domain(domain, max_queue_size, queue):
                            await queue.put(url)

        except Exception as exc:
            connected_event.clear()
            logger.warning(
                "certstream connection error (%s): %s — retrying in %ds",
                type(exc).__name__, exc, retry_delay,
            )
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)


async def _poll_crtsh(
    queue: asyncio.Queue,
    max_queue_size: int,
    interesting_only: bool,
    poll_interval: int = 60,
) -> None:
    """
    Poll crt.sh for recently issued certificates.

    For each new domain found, generate the full sensitive-path probe
    list and push all probe URLs to the queue.
    """
    timeout = aiohttp.ClientTimeout(total=30)
    _seen_ids: set[int] = set()
    _MAX_SEEN = 50_000

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {
                    "q": "%",
                    "output": "json",
                    "exclude": "expired",
                    "limit": "100",
                }
                async with session.get(CRTSH_API, params=params) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = []
                            for line in text.strip().splitlines():
                                try:
                                    data.append(json.loads(line))
                                except Exception:
                                    pass

                        new_domains: set[str] = set()
                        for cert in data:
                            cert_id = cert.get("id", 0)
                            if cert_id and cert_id in _seen_ids:
                                continue
                            if cert_id:
                                _seen_ids.add(cert_id)
                                if len(_seen_ids) > _MAX_SEEN:
                                    _seen_ids = set(list(_seen_ids)[_MAX_SEEN // 2:])

                            for field in ("name_value", "common_name"):
                                for part in cert.get(field, "").split("\n"):
                                    part = part.strip().lstrip("*.")
                                    if part and "." in part and not part.startswith(" "):
                                        new_domains.add(part)

                        probe_count = 0
                        for domain in new_domains:
                            if interesting_only and not _is_interesting(domain):
                                continue
                            for url in _expand_domain(domain, max_queue_size, queue):
                                await queue.put(url)
                                probe_count += 1

                        if probe_count:
                            logger.info(
                                "crt.sh poll: %d domains → %d probe URLs queued",
                                len(new_domains), probe_count,
                            )
                        else:
                            logger.debug("crt.sh poll: no new domains")
                    else:
                        logger.debug("crt.sh returned HTTP %d", resp.status)

            except Exception as exc:
                logger.debug("crt.sh poll error (%s): %s", type(exc).__name__, exc)

            await asyncio.sleep(poll_interval)


async def stream_ct_hostnames(
    queue: asyncio.Queue,
    max_queue_size: int = 5000,
    interesting_only: bool = False,
) -> None:
    """
    Continuously stream sensitive-path probe URLs derived from CT log entries.

    Runs two concurrent tasks:
      1. certstream WebSocket — real-time, high-volume (primary)
      2. crt.sh polling — reliable fallback, polls every 60s

    Each discovered hostname is expanded into ~29 probe URLs covering
    common sensitive paths (.env, wp-config.php, .git/config, etc.).
    """
    connected_event = asyncio.Event()

    await asyncio.gather(
        _stream_certstream(queue, max_queue_size, interesting_only, connected_event),
        _poll_crtsh(queue, max_queue_size, interesting_only, poll_interval=60),
    )
