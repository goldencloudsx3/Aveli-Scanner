"""
Supplementary URL feed sources.

Aggregates targets from multiple public threat-intel / discovery feeds:
  - AlienVault OTX pulse indicators
  - URLScan.io live search
  - Shodan InternetDB (IP enrichment only — no API key needed)
  - PhishTank newly submitted phishing URLs
  - OpenPhish feed
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp

logger = logging.getLogger("aveli.url_feeds")


# ---------------------------------------------------------------------------
# URLScan.io — public search, no auth needed for basic queries
# ---------------------------------------------------------------------------

async def stream_urlscan(
    queue: asyncio.Queue,
    query: str = "page.status:200 AND NOT page.url:google.com",
    max_results: int = 200,
    interval_seconds: int = 300,
    max_queue_size: int = 5000,
) -> None:
    """Poll URLScan.io for recently scanned pages matching the query."""
    base_url = "https://urlscan.io/api/v1/search/"
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {"q": query, "size": str(max_results), "sort": "_score"}
                async with session.get(base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for result in data.get("results", []):
                            url = result.get("page", {}).get("url", "")
                            if url and queue.qsize() < max_queue_size:
                                await queue.put(url)
                        logger.debug("URLScan.io yielded %d URLs", len(data.get("results", [])))
            except Exception as exc:
                logger.debug("URLScan feed error: %s", exc)

            await asyncio.sleep(interval_seconds)


# ---------------------------------------------------------------------------
# OpenPhish — free phishing URL feed (updated every 12h)
# ---------------------------------------------------------------------------

async def stream_openphish(
    queue: asyncio.Queue,
    interval_seconds: int = 43200,
    max_queue_size: int = 5000,
) -> None:
    """Fetch OpenPhish feed and enqueue phishing URLs for credential-exposure scanning."""
    feed_url = "https://openphish.com/feed.txt"
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                async with session.get(feed_url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        count = 0
                        for line in text.splitlines():
                            url = line.strip()
                            if url.startswith("http") and queue.qsize() < max_queue_size:
                                await queue.put(url)
                                count += 1
                        logger.info("OpenPhish feed loaded %d URLs", count)
            except Exception as exc:
                logger.debug("OpenPhish feed error: %s", exc)

            await asyncio.sleep(interval_seconds)


# ---------------------------------------------------------------------------
# Alexa/Tranco top-sites probe (static seed for baseline coverage)
# ---------------------------------------------------------------------------

_TOP_SITE_PROBE_PATHS = [
    "/.env",
    "/wp-config.php",
    "/.git/config",
    "/config.php",
    "/phpinfo.php",
    "/graphql",
    "/.npmrc",
    "/backup.sql",
    "/credentials.json",
    "/secrets.yml",
    "/database.yml",
    "/api/v1/users",
    "/api/users",
    "/swagger.json",
    "/openapi.json",
    "/v1/keys",
    "/health",
    "/debug",
    "/console",
    "/adminer.php",
    "/phpmyadmin/",
]


async def probe_top_sites(
    queue: asyncio.Queue,
    max_queue_size: int = 5000,
) -> None:
    """
    Generate sensitive-path probes for a curated list of high-value targets
    from the Tranco top-1M list (first 500 fetched on demand).
    """
    tranco_url = "https://tranco-list.eu/api/lists/daily"
    top_domains: list[str] = []

    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(tranco_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    list_id = data.get("list_id", "")
                    if list_id:
                        list_url = f"https://tranco-list.eu/download_daily/{list_id}/500"
                        async with session.get(list_url) as lr:
                            if lr.status == 200:
                                text = await lr.text()
                                for line in text.splitlines()[:500]:
                                    parts = line.split(",")
                                    if len(parts) >= 2:
                                        top_domains.append(parts[1].strip())
    except Exception as exc:
        logger.debug("Tranco fetch error: %s", exc)

    if not top_domains:
        # Hardcoded fallback seed — common high-value targets
        top_domains = [
            "github.com", "gitlab.com", "npmjs.com", "pypi.org",
            "coinbase.com", "binance.com", "kraken.com", "opensea.io",
        ]

    for domain in top_domains:
        for path in _TOP_SITE_PROBE_PATHS:
            url = f"https://{domain}{path}"
            if queue.qsize() < max_queue_size:
                await queue.put(url)
