"""
Common Crawl CDX API source.

Queries the Common Crawl index to find recently crawled URLs
matching patterns for sensitive files (.env, config files, etc.)
and high-value domains.
"""

import asyncio
import json
import logging

import aiohttp

logger = logging.getLogger("aveli.common_crawl")

# Common Crawl CDX API — collinfo.json lists all available indexes newest-first
CDX_SEARCH = "https://index.commoncrawl.org/collinfo.json"
# Fallback: a recent known-good index (updated periodically)
CDX_API_FALLBACK = "https://index.commoncrawl.org/CC-MAIN-2025-08-index"

# Sensitive URL patterns to hunt for in the crawl index
_SENSITIVE_PATTERNS = [
    "*.env",
    "*/.env",
    "*/wp-config.php",
    "*/config.php",
    "*/.git/config",
    "*/database.yml",
    "*/secrets.yml",
    "*/credentials.json",
    "*/phpinfo.php",
    "*/admin/config",
    "*/backup.sql",
    "*/dump.sql",
    "*/.npmrc",
    "*/graphql",
]


async def _get_latest_index(session: aiohttp.ClientSession) -> str:
    """Fetch the URL of the most recent Common Crawl index."""
    try:
        async with session.get(CDX_SEARCH, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data:
                    index_url = data[0].get("cdx-api", "")
                    if index_url:
                        logger.info("Using Common Crawl index: %s", index_url)
                        return index_url
    except Exception as exc:
        logger.warning("Failed to fetch CC index list: %s — using fallback index", exc)
    logger.info("Using Common Crawl fallback index: %s", CDX_API_FALLBACK)
    return CDX_API_FALLBACK


async def query_sensitive_urls(
    queue: asyncio.Queue,
    limit_per_pattern: int = 100,
    max_queue_size: int = 5000,
) -> None:
    """Query Common Crawl CDX for known-sensitive URL patterns."""
    connector = aiohttp.TCPConnector(limit=5)
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        index_url = await _get_latest_index(session)

        for pattern in _SENSITIVE_PATTERNS:
            try:
                params = {
                    "url": pattern,
                    "output": "json",
                    "fl": "url,status,timestamp",
                    "limit": str(limit_per_pattern),
                    "filter": "statuscode:200",
                }
                async with session.get(index_url, params=params) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()
                    for line in text.strip().splitlines():
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                            url = record.get("url", "")
                            if url and queue.qsize() < max_queue_size:
                                await queue.put(url)
                        except Exception:
                            continue
                await asyncio.sleep(0.5)  # polite crawl delay
            except Exception as exc:
                logger.debug("CDX query error for %s: %s", pattern, exc)


async def stream_common_crawl(
    queue: asyncio.Queue,
    interval_seconds: int = 3600,
    max_queue_size: int = 5000,
) -> None:
    """Periodically pull from Common Crawl CDX and feed URLs to the queue."""
    while True:
        logger.info("Starting Common Crawl CDX sweep…")
        await query_sensitive_urls(queue, max_queue_size=max_queue_size)
        logger.info("Common Crawl sweep done. Next run in %ds", interval_seconds)
        await asyncio.sleep(interval_seconds)
