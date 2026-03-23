"""
Certificate Transparency Log monitor.

Streams newly issued TLS certificates from certstream WebSocket feed,
yielding fresh hostnames to scan. New cert issuance is a strong signal
that a site is newly deployed or updated.

Falls back to crt.sh polling if the certstream WebSocket is unavailable.
"""

import asyncio
import json
import logging
import ssl
from typing import AsyncIterator

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


def _is_interesting(hostname: str) -> bool:
    """Return True if the hostname looks worth scanning."""
    hostname_lower = hostname.lower()
    # Skip wildcards and extremely generic names
    if hostname_lower.startswith("*.") or hostname_lower in {"localhost", "example.com"}:
        return False
    # Prioritise keywords associated with high-value targets
    for kw in _HIGH_VALUE_KEYWORDS:
        if kw in hostname_lower:
            return True
    return False


async def _stream_certstream(
    queue: asyncio.Queue,
    max_queue_size: int,
    interesting_only: bool,
    connected_event: asyncio.Event,
) -> None:
    """Connect to certstream WebSocket and push hostnames to queue."""
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
                retry_delay = 2  # reset on successful connect
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
                        if queue.qsize() < max_queue_size:
                            await queue.put(f"https://{domain}")

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
    Poll crt.sh for recently issued certificates as a fallback CT source.

    crt.sh is a reliable public CT log search engine. We query for recently
    logged certs and extract hostnames. This runs permanently in case
    certstream is unavailable or returns sparse data.
    """
    timeout = aiohttp.ClientTimeout(total=30)
    # Deduplicate within a polling window
    _seen_ids: set[int] = set()
    _MAX_SEEN = 50_000

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {
                    "q": "%",           # all domains
                    "output": "json",
                    "exclude": "expired",
                    "limit": "100",
                }
                async with session.get(CRTSH_API, params=params) as resp:
                    if resp.status == 200:
                        # crt.sh returns newline-delimited JSON objects
                        text = await resp.text()
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            # Try parsing as newline-delimited JSON
                            data = []
                            for line in text.strip().splitlines():
                                try:
                                    data.append(json.loads(line))
                                except Exception:
                                    pass

                        count = 0
                        for cert in data:
                            cert_id = cert.get("id", 0)
                            if cert_id and cert_id in _seen_ids:
                                continue
                            if cert_id:
                                _seen_ids.add(cert_id)
                                if len(_seen_ids) > _MAX_SEEN:
                                    # Keep only the newest half
                                    _seen_ids = set(list(_seen_ids)[_MAX_SEEN // 2:])

                            name_value = cert.get("name_value", "")
                            common_name = cert.get("common_name", "")
                            candidates = set()
                            for raw in [name_value, common_name]:
                                for part in raw.split("\n"):
                                    part = part.strip().lstrip("*.")
                                    if part and "." in part and not part.startswith(" "):
                                        candidates.add(part)

                            for domain in candidates:
                                if interesting_only and not _is_interesting(domain):
                                    continue
                                if queue.qsize() < max_queue_size:
                                    await queue.put(f"https://{domain}")
                                    count += 1

                        if count:
                            logger.info("crt.sh poll yielded %d new hostnames", count)
                        else:
                            logger.debug("crt.sh poll: no new hostnames")
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
    Continuously stream new hostnames from Certificate Transparency logs
    and push them onto `queue`.

    Runs two concurrent tasks:
      1. certstream WebSocket — real-time, high-volume (primary)
      2. crt.sh polling — reliable fallback, polls every 60s
    """
    connected_event = asyncio.Event()

    await asyncio.gather(
        _stream_certstream(queue, max_queue_size, interesting_only, connected_event),
        _poll_crtsh(queue, max_queue_size, interesting_only, poll_interval=60),
    )
