"""
AWS S3 public-bucket discovery source.

Feeds S3 bucket root URLs into the scan queue from three data sources:

  1. URLScan.io  — live search for recently scanned S3 URLs
  2. crt.sh      — Certificate Transparency logs filtered to *.s3.amazonaws.com
  3. Common Crawl CDX — historical index query for s3.amazonaws.com patterns

Each discovered URL is the bucket root (https://<bucket>.s3.amazonaws.com/)
so the scanner can check for public listing (ListBucketResult XML).
"""

import asyncio
import json
import logging
import re

import aiohttp

logger = logging.getLogger("aveli.s3_buckets")

# Only accept well-formed S3 virtual-hosted bucket hostnames
_BUCKET_HOST_RE = re.compile(
    r"^[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]\.s3[.\-]"
    r"(?:[a-z0-9\-]+\.)?amazonaws\.com$",
    re.IGNORECASE,
)


def _bucket_root(raw_url: str) -> str:
    """Normalise any S3 URL to its bucket root (scheme + host + '/')."""
    from urllib.parse import urlparse
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        return ""
    if not _BUCKET_HOST_RE.match(parsed.netloc):
        return ""
    return f"https://{parsed.netloc}/"


async def _stream_urlscan_s3(
    queue: asyncio.Queue,
    max_queue_size: int,
    interval_seconds: int,
) -> None:
    """Poll URLScan.io for recently scanned S3 bucket pages."""
    base_url = "https://urlscan.io/api/v1/search/"
    # Query for pages served directly from S3 virtual-hosted endpoints
    query = 'page.domain:s3.amazonaws.com AND page.status:200'
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {"q": query, "size": "200", "sort": "_score"}
                async with session.get(base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        seen: set[str] = set()
                        for result in data.get("results", []):
                            raw = result.get("page", {}).get("url", "")
                            root = _bucket_root(raw)
                            if root and root not in seen:
                                seen.add(root)
                                if queue.qsize() < max_queue_size:
                                    await queue.put(root)
                        logger.debug(
                            "URLScan S3 feed: %d unique bucket roots", len(seen)
                        )
                    elif resp.status == 429:
                        logger.debug("URLScan S3: rate-limited, backing off")
                        await asyncio.sleep(60)
                        continue
            except Exception as exc:
                logger.debug("URLScan S3 feed error: %s", exc)

            await asyncio.sleep(interval_seconds)


async def _stream_crtsh_s3(
    queue: asyncio.Queue,
    max_queue_size: int,
    poll_interval: int,
) -> None:
    """
    Poll crt.sh for CT log entries matching *.s3.amazonaws.com.

    AWS issues real TLS certificates for virtual-hosted S3 buckets, so
    every new bucket eventually appears in the CT logs.
    """
    timeout = aiohttp.ClientTimeout(total=30)
    _seen_ids: set[int] = set()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {
                    "q": "%.s3.amazonaws.com",
                    "output": "json",
                    "exclude": "expired",
                    "limit": "200",
                }
                async with session.get("https://crt.sh/", params=params) as resp:
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

                        count = 0
                        for cert in data:
                            cert_id = cert.get("id", 0)
                            if cert_id and cert_id in _seen_ids:
                                continue
                            if cert_id:
                                _seen_ids.add(cert_id)
                                if len(_seen_ids) > 50_000:
                                    _seen_ids = set(list(_seen_ids)[25_000:])

                            for field in ("name_value", "common_name"):
                                raw = cert.get(field, "")
                                for part in raw.split("\n"):
                                    part = part.strip().lstrip("*.")
                                    if not _BUCKET_HOST_RE.match(part):
                                        continue
                                    root = f"https://{part}/"
                                    if queue.qsize() < max_queue_size:
                                        await queue.put(root)
                                        count += 1

                        if count:
                            logger.info(
                                "crt.sh S3 poll: %d new bucket URLs", count
                            )
            except Exception as exc:
                logger.debug("crt.sh S3 poll error: %s", exc)

            await asyncio.sleep(poll_interval)


async def _stream_commoncrawl_s3(
    queue: asyncio.Queue,
    max_queue_size: int,
    interval_seconds: int,
) -> None:
    """
    Query the Common Crawl CDX index for historically crawled S3 bucket URLs.

    Runs once on startup then sleeps for interval_seconds before repeating.
    """
    CDX_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
    CDX_FALLBACK = "https://index.commoncrawl.org/CC-MAIN-2025-08/cdx"
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Resolve the latest CDX API endpoint once
        cdx_api = CDX_FALLBACK
        try:
            async with session.get(CDX_COLLINFO) as resp:
                if resp.status == 200:
                    info = await resp.json()
                    if info:
                        cdx_api = info[0].get("cdx-api", CDX_FALLBACK)
        except Exception as exc:
            logger.debug("CC collinfo fetch error: %s — using fallback", exc)

        while True:
            try:
                params = {
                    "url": "*.s3.amazonaws.com/*",
                    "output": "json",
                    "fl": "url",
                    "limit": "500",
                    "filter": "statuscode:200",
                    "collapse": "urlkey",  # deduplicate by URL key
                }
                async with session.get(cdx_api, params=params) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        seen: set[str] = set()
                        for line in text.strip().splitlines():
                            if not line.strip():
                                continue
                            try:
                                record = json.loads(line)
                                raw = record.get("url", "")
                                root = _bucket_root(raw)
                                if root and root not in seen:
                                    seen.add(root)
                                    if queue.qsize() < max_queue_size:
                                        await queue.put(root)
                            except Exception:
                                continue
                        logger.debug(
                            "Common Crawl S3 sweep: %d bucket roots", len(seen)
                        )
            except Exception as exc:
                logger.debug("Common Crawl S3 error: %s", exc)

            await asyncio.sleep(interval_seconds)


async def stream_s3_buckets(
    queue: asyncio.Queue,
    max_queue_size: int = 5_000,
    urlscan_interval: int = 300,
    crtsh_interval: int = 120,
    commoncrawl_interval: int = 3600,
) -> None:
    """
    Continuously stream newly discovered S3 bucket root URLs into `queue`.

    Runs three concurrent sub-tasks:
      - URLScan.io live search (every 5 min)
      - crt.sh CT log polling  (every 2 min)
      - Common Crawl CDX sweep (every hour)
    """
    await asyncio.gather(
        _stream_urlscan_s3(queue, max_queue_size, urlscan_interval),
        _stream_crtsh_s3(queue, max_queue_size, crtsh_interval),
        _stream_commoncrawl_s3(queue, max_queue_size, commoncrawl_interval),
    )
