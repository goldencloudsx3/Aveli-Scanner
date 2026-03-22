"""
Async scanner core.

Workers pull URLs from the discovery queue, fetch page content,
run all detectors, and push findings to the results queue.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from .detectors.secrets import Finding, Severity, scan_content, scan_url
from .detectors.headers import scan_headers

logger = logging.getLogger("aveli.scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ScannerConfig:
    # Concurrency
    workers: int = 20
    request_timeout: int = 12          # seconds per request
    max_content_bytes: int = 512_000   # 512 KB max body read

    # Filtering — only report findings at or above this severity
    min_severity: Severity = Severity.HIGH

    # Rate limiting
    requests_per_second: float = 20.0

    # Retry
    max_retries: int = 1

    # HTTP
    user_agent: str = (
        "Mozilla/5.0 (compatible; AveliScanner/1.0; +https://github.com/aveli/scanner)"
    )
    follow_redirects: bool = True
    verify_ssl: bool = True

    # Which checks to run
    check_headers: bool = True
    check_content: bool = True
    check_url_patterns: bool = True

    # Severity filter — only report at or above this level
    severity_filter: set[Severity] = field(default_factory=lambda: {
        Severity.CRITICAL, Severity.HIGH
    })


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class ScanStats:
    urls_scanned: int = 0
    urls_errored: int = 0
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        e = self.elapsed
        return self.urls_scanned / e if e > 0 else 0.0


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / max(rps, 0.01)
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# URL deduplication
# ---------------------------------------------------------------------------

class UrlDeduper:
    def __init__(self, max_size: int = 100_000):
        self._seen: set[str] = set()
        self._max = max_size

    def seen(self, url: str) -> bool:
        key = self._normalise(url)
        if key in self._seen:
            return True
        if len(self._seen) >= self._max:
            # Cache full: evict ~10 % of entries to make room and prevent unbounded re-scanning
            remove = set(list(self._seen)[: self._max // 10])
            self._seen -= remove
        self._seen.add(key)
        return False

    @staticmethod
    def _normalise(url: str) -> str:
        parsed = urlparse(url.lower().rstrip("/"))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    config: ScannerConfig,
    rate_limiter: RateLimiter,
) -> tuple[Optional[str], Optional[dict], int]:
    """Fetch a URL and return (body_text, headers_dict, status_code)."""
    await rate_limiter.acquire()

    for attempt in range(config.max_retries + 1):
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=config.request_timeout),
                allow_redirects=config.follow_redirects,
                ssl=config.verify_ssl,
            ) as resp:
                headers = dict(resp.headers)
                status = resp.status

                if status not in (200, 206):
                    return None, headers, status

                # Read up to max_content_bytes
                body = await resp.content.read(config.max_content_bytes)
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:
                    text = ""

                return text, headers, status

        except asyncio.TimeoutError:
            return None, None, 0
        except aiohttp.ClientConnectorError:
            return None, None, 0
        except Exception as exc:
            if attempt < config.max_retries:
                await asyncio.sleep(1)
            else:
                logger.debug("Fetch error for %s: %s", url, exc)
                return None, None, 0

    return None, None, 0


async def scan_worker(
    worker_id: int,
    url_queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    config: ScannerConfig,
    stats: ScanStats,
    deduper: UrlDeduper,
    rate_limiter: RateLimiter,
) -> None:
    """Single async worker: consume URLs, scan, emit findings."""
    connector = aiohttp.TCPConnector(limit=0, ssl=False, ttl_dns_cache=300)
    headers = {
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        while True:
            try:
                url: str = await asyncio.wait_for(url_queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue

            try:
                if deduper.seen(url):
                    continue

                # URL-pattern checks (no HTTP request needed)
                if config.check_url_patterns:
                    url_findings = scan_url(url)
                    for f in url_findings:
                        if f.severity in config.severity_filter:
                            await result_queue.put(f)
                            _update_finding_stats(stats, f)

                # HTTP fetch
                body, resp_headers, status = await _fetch(session, url, config, rate_limiter)
                stats.urls_scanned += 1

                if body is None and resp_headers is None:
                    stats.urls_errored += 1
                    continue

                # Header analysis — only for successful responses to avoid false positives
                if config.check_headers and resp_headers and status in (200, 206):
                    header_findings = scan_headers(url, resp_headers)
                    for f in header_findings:
                        if f.severity in config.severity_filter:
                            await result_queue.put(f)
                            _update_finding_stats(stats, f)

                # Content analysis
                if config.check_content and body:
                    content_findings = scan_content(url, body)
                    for f in content_findings:
                        if f.severity in config.severity_filter:
                            await result_queue.put(f)
                            _update_finding_stats(stats, f)

            except Exception as exc:
                logger.debug("Worker %d error on %s: %s", worker_id, url, exc)
                stats.urls_errored += 1
            finally:
                url_queue.task_done()


def _update_finding_stats(stats: ScanStats, finding: Finding) -> None:
    stats.findings_total += 1
    if finding.severity == Severity.CRITICAL:
        stats.findings_critical += 1
    elif finding.severity == Severity.HIGH:
        stats.findings_high += 1


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

class AveliScanner:
    """
    Orchestrates URL discovery sources, worker pool, and result consumers.
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.url_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self.result_queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
        self.stats = ScanStats()
        self._deduper = UrlDeduper()
        self._rate_limiter = RateLimiter(self.config.requests_per_second)
        self._tasks: list[asyncio.Task] = []

    async def start(
        self,
        enable_ct_logs: bool = True,
        enable_common_crawl: bool = True,
        enable_urlscan: bool = True,
        enable_openphish: bool = False,
        enable_top_sites_probe: bool = True,
        extra_urls: Optional[list[str]] = None,
    ) -> None:
        """Start all source tasks and worker pool."""
        # Seed extra URLs
        if extra_urls:
            for url in extra_urls:
                await self.url_queue.put(url)

        # Source tasks
        if enable_ct_logs:
            from .sources.ct_logs import stream_ct_hostnames
            self._tasks.append(
                asyncio.create_task(
                    stream_ct_hostnames(self.url_queue), name="ct-logs"
                )
            )

        if enable_common_crawl:
            from .sources.common_crawl import stream_common_crawl
            self._tasks.append(
                asyncio.create_task(
                    stream_common_crawl(self.url_queue), name="common-crawl"
                )
            )

        if enable_urlscan:
            from .sources.url_feeds import stream_urlscan
            self._tasks.append(
                asyncio.create_task(stream_urlscan(self.url_queue), name="urlscan")
            )

        if enable_openphish:
            from .sources.url_feeds import stream_openphish
            self._tasks.append(
                asyncio.create_task(stream_openphish(self.url_queue), name="openphish")
            )

        if enable_top_sites_probe:
            from .sources.url_feeds import probe_top_sites
            self._tasks.append(
                asyncio.create_task(probe_top_sites(self.url_queue), name="top-sites")
            )

        # Worker pool
        for i in range(self.config.workers):
            self._tasks.append(
                asyncio.create_task(
                    scan_worker(
                        worker_id=i,
                        url_queue=self.url_queue,
                        result_queue=self.result_queue,
                        config=self.config,
                        stats=self.stats,
                        deduper=self._deduper,
                        rate_limiter=self._rate_limiter,
                    ),
                    name=f"worker-{i}",
                )
            )

    async def stop(self) -> None:
        """Cancel all running tasks."""
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
