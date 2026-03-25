"""
Wayback Machine (archive.org) CDX API source.

Queries the Internet Archive's CDX search API for URLs matching
sensitive file patterns that were actually crawled and returned HTTP 200.
Unlike Common Crawl, the Wayback Machine CDX API:
  - Requires no authentication
  - Is always available
  - Returns results immediately with no cold-start
  - Covers billions of pages spanning decades of crawls

We query for patterns like *.env, wp-config.php, .git/config etc.
across all domains, deduplicate by URL, and push to the scan queue.
The scanner then re-fetches the live URL — if it still returns 200,
there's a real finding.
"""

import asyncio
import json
import logging

import aiohttp

logger = logging.getLogger("aveli.wayback")

CDX_API = "https://web.archive.org/cdx/search/cdx"

# Sensitive patterns to query — each becomes one CDX API call.
# Ordered by highest expected yield / impact.
_PATTERNS = [
    "*/.env",
    "*/wp-config.php",
    "*/.git/config",
    "*/config.php",
    "*/database.yml",
    "*/secrets.yml",
    "*/credentials.json",
    "*/.npmrc",
    "*/backup.sql",
    "*/dump.sql",
    "*/.htpasswd",
    "*/phpinfo.php",
    "*/adminer.php",
    "*/phpmyadmin/index.php",
    "*/swagger.json",
    "*/openapi.json",
    "*/graphql",
    "*/api/v1/users",
    "*/debug",
    "*/console",
    "*/.aws/credentials",
    "*/server-status",
    "*/elmah.axd",
    "*/trace.axd",
    "*/.DS_Store",
    "*/id_rsa",
    "*/private.key",
    "*/private.pem",
]


async def stream_wayback(
    queue: asyncio.Queue,
    max_queue_size: int = 5_000,
    limit_per_pattern: int = 500,
    interval_seconds: int = 1800,
) -> None:
    """
    Continuously query the Wayback Machine CDX API for sensitive URLs.

    Each sweep queries every pattern, deduplicates results, and pushes
    live URLs (not wayback replay URLs) to the scan queue.
    Repeats every interval_seconds (default 30 min).
    """
    timeout = aiohttp.ClientTimeout(total=45)
    connector = aiohttp.TCPConnector(limit=5)

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout
    ) as session:
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
                        "collapse": "urlkey",   # one URL per unique path
                        "fastLatest": "true",   # skip old snapshots, get newest
                    }
                    async with session.get(CDX_API, params=params) as resp:
                        if resp.status != 200:
                            logger.debug(
                                "Wayback CDX returned %d for pattern %s",
                                resp.status, pattern,
                            )
                            continue

                        text = await resp.text()
                        lines = text.strip().splitlines()
                        # First line is the header ["original"], skip it
                        if lines and lines[0].startswith("["):
                            lines = lines[1:]

                        for line in lines:
                            line = line.strip().strip(",")
                            if not line:
                                continue
                            try:
                                row = json.loads(line)
                                # row is ["url"] after stripping header
                                url = row[0] if isinstance(row, list) else ""
                            except (json.JSONDecodeError, IndexError):
                                # Plain text fallback
                                url = line.strip('"[] ,')

                            if url.startswith("http") and queue.qsize() < max_queue_size:
                                await queue.put(url)
                                total += 1

                    await asyncio.sleep(0.5)  # polite delay between patterns

                except Exception as exc:
                    logger.debug("Wayback CDX error for %s: %s", pattern, exc)

            if total:
                logger.info("Wayback CDX sweep complete: %d URLs queued", total)
            else:
                logger.debug("Wayback CDX sweep: no new URLs")

            await asyncio.sleep(interval_seconds)
