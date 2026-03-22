"""
Certificate Transparency Log monitor.

Streams newly issued TLS certificates from certstream WebSocket feed,
yielding fresh hostnames to scan. New cert issuance is a strong signal
that a site is newly deployed or updated.
"""

import asyncio
import json
import logging
from typing import AsyncIterator

import tldextract

logger = logging.getLogger("aveli.ct_logs")

# Public certstream-community WebSocket endpoint
CT_STREAM_URL = "wss://certstream.calidog.io/"

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


async def stream_ct_hostnames(
    queue: asyncio.Queue,
    max_queue_size: int = 5000,
    interesting_only: bool = False,
) -> None:
    """
    Continuously stream new hostnames from Certificate Transparency logs
    and push them onto `queue`.

    Falls back to a polling-based approach if WebSocket is unavailable.
    """
    try:
        import websockets  # type: ignore
    except ImportError:
        logger.warning("websockets not installed; CT log streaming disabled. pip install websockets")
        return

    retry_delay = 2
    while True:
        try:
            logger.info("Connecting to CT log stream: %s", CT_STREAM_URL)
            async with websockets.connect(
                CT_STREAM_URL,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
            ) as ws:
                retry_delay = 2  # reset on successful connect
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
            logger.warning("CT stream error (%s): %s. Retrying in %ds…", type(exc).__name__, exc, retry_delay)
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)
