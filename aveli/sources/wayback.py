"""
Wayback Machine (archive.org) CDX API source.

Strategy: ask the CDX API for URLs matching sensitive-file patterns that
historically returned HTTP 200, then re-probe the LIVE URL (not the archive
replay) to check if the file is still exposed.  This is the highest
signal-to-noise approach available without API keys because every result
was a real exposure at least once.

CDX API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
"""

import asyncio
import json
import logging

import aiohttp

logger = logging.getLogger("aveli.wayback")

CDX_API = "https://web.archive.org/cdx/search/cdx"

# Sensitive patterns — each becomes one API call.
# Wildcard prefix covers all domains. 200-only filter cuts noise.
_PATTERNS = [
    "*/.env",
    "*/.env.local",
    "*/.env.production",
    "*/wp-config.php",
    "*/.git/config",
    "*/config.php",
    "*/database.yml",
    "*/secrets.yml",
    "*/credentials.json",
    "*/.npmrc",
    "*/.aws/credentials",
    "*/.htpasswd",
    "*/backup.sql",
    "*/dump.sql",
    "*/phpinfo.php",
    "*/adminer.php",
    "*/id_rsa",
    "*/private.key",
    "*/server-status",
]


def _parse_cdx_response(text: str) -> list[str]:
    """
    Parse CDX JSON response into a list of original URLs.

    The API returns either:
      a) A JSON array of arrays: [["original"], ["http://..."], ...]
      b) Plain text, one URL per line (when output=text)

    We request output=json so expect (a).
    """
    text = text.strip()
    if not text:
        return []

    # Try full JSON parse first (most reliable)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            urls = []
            for row in data[1:]:   # skip header row ["original"]
                if isinstance(row, list) and row:
                    url = row[0]
                    if isinstance(url, str) and url.startswith("http"):
                        urls.append(url)
            return urls
    except json.JSONDecodeError:
        pass

    # Fallback: try line-by-line (some CDX endpoints use NDJSON)
    urls = []
    for line in text.splitlines():
        line = line.strip().strip('[],"')
        if line.startswith("http"):
            urls.append(line)
        else:
            try:
                row = json.loads(line)
                if isinstance(row, list) and row and isinstance(row[0], str):
                    if row[0].startswith("http"):
                        urls.append(row[0])
            except Exception:
                pass
    return urls


async def stream_wayback(
    queue: asyncio.Queue,
    max_queue_size: int = 5_000,
    limit_per_pattern: int = 300,
    interval_seconds: int = 1800,
) -> None:
    """
    Query the Wayback Machine CDX for historically-exposed sensitive files
    and push the live URLs to the scan queue.  Repeats every 30 minutes.
    """
    # Use a separate connector with a low limit so this source doesn't
    # compete for file descriptors with the main scanner session.
    connector = aiohttp.TCPConnector(limit=5)
    timeout = aiohttp.ClientTimeout(total=45)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        while True:
            total = 0
            for pattern in _PATTERNS:
                try:
                    params = {
                        "url": pattern,
                        "output": "json",
                        "fl": "original",
                        "filter": "statuscode:200",
                        "limit": str(limit_per_pattern),
                        "collapse": "urlkey",   # deduplicate same path across snapshots
                    }
                    async with session.get(CDX_API, params=params) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            urls = _parse_cdx_response(text)
                            for url in urls:
                                if queue.qsize() < max_queue_size:
                                    await queue.put(url)
                                    total += 1
                            logger.debug(
                                "Wayback CDX %s → %d URLs", pattern, len(urls)
                            )
                        elif resp.status == 429:
                            logger.debug("Wayback CDX rate-limited, sleeping 30s")
                            await asyncio.sleep(30)
                        else:
                            logger.debug("Wayback CDX %d for %s", resp.status, pattern)

                    await asyncio.sleep(1)   # polite delay between patterns

                except Exception as exc:
                    logger.debug("Wayback CDX error for %s: %s", pattern, exc)

            logger.info("Wayback CDX sweep done: %d URLs queued", total)
            await asyncio.sleep(interval_seconds)
