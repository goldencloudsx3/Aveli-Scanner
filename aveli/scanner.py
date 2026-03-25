"""
Async scanner core.

Key design decisions
--------------------
* ONE shared aiohttp.ClientSession with a capped TCPConnector is created
  in AveliScanner and passed to every worker.  The previous design gave
  each worker its own connector, which burned through macOS's 256 default
  file-descriptor limit in under a second, causing 100 % connection errors.

* Default workers dropped to 8 (plenty for a 10 req/s rate limit and safe
  on Mac without adjusting ulimit).

* Three focused URL sources (Wayback CDX, crt.sh active probing, S3) —
  all reliable, no external API keys required.
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
from .detectors.s3 import scan_s3_response, is_s3_url

logger = logging.getLogger("aveli.scanner")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ScannerConfig:
    # Concurrency — keep workers low; the bottleneck is network, not CPU
    workers: int = 8
    request_timeout: int = 10
    max_content_bytes: int = 256_000   # 256 KB is plenty for secrets

    # Rate limiting — polite default; increase with --rps if needed
    requests_per_second: float = 10.0

    # Retry — one retry is enough; bad hosts stay bad
    max_retries: int = 1

    # HTTP
    user_agent: str = (
        "Mozilla/5.0 (compatible; AveliScanner/1.0; +https://github.com/aveli/scanner)"
    )
    follow_redirects: bool = True
    verify_ssl: bool = False   # many targets have cert issues; scan them anyway

    # Connection pool — shared across ALL workers; keeps FDs under control
    max_connections: int = 50  # total concurrent TCP connections

    # Which checks to run
    check_headers: bool = True
    check_content: bool = True
    check_url_patterns: bool = True
    check_s3: bool = True

    # Severity filter
    min_severity: Severity = Severity.HIGH
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
    def __init__(self, max_size: int = 200_000):
        self._seen: set[str] = set()
        self._max = max_size

    def seen(self, url: str) -> bool:
        key = self._normalise(url)
        if key in self._seen:
            return True
        if len(self._seen) >= self._max:
            # Evict oldest 10 %
            remove = set(list(self._seen)[: self._max // 10])
            self._seen -= remove
        self._seen.add(key)
        return False

    @staticmethod
    def _normalise(url: str) -> str:
        p = urlparse(url.lower().rstrip("/"))
        return f"{p.scheme}://{p.netloc}{p.path}"


# ---------------------------------------------------------------------------
# HTTP fetch — uses the shared session passed in
# ---------------------------------------------------------------------------

async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    config: ScannerConfig,
    rate_limiter: RateLimiter,
) -> tuple[Optional[str], Optional[dict], int]:
    """Return (body, headers, status).  body is None for non-200 responses."""
    await rate_limiter.acquire()

    for attempt in range(config.max_retries + 1):
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=config.request_timeout),
                allow_redirects=config.follow_redirects,
                ssl=False,   # verify_ssl handled at session level via connector
            ) as resp:
                headers = dict(resp.headers)
                status = resp.status

                if status not in (200, 206):
                    return None, headers, status

                body_bytes = await resp.content.read(config.max_content_bytes)
                text = body_bytes.decode("utf-8", errors="replace")
                return text, headers, status

        except (asyncio.TimeoutError, aiohttp.ClientConnectorError,
                aiohttp.ServerDisconnectedError, aiohttp.ClientOSError):
            return None, None, 0
        except aiohttp.TooManyRedirects:
            return None, None, 0
        except Exception as exc:
            if attempt < config.max_retries:
                await asyncio.sleep(0.5)
            else:
                logger.debug("fetch error %s: %s", url, exc)
                return None, None, 0

    return None, None, 0


# ---------------------------------------------------------------------------
# Worker — receives the shared session
# ---------------------------------------------------------------------------

async def scan_worker(
    worker_id: int,
    url_queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    session: aiohttp.ClientSession,
    config: ScannerConfig,
    stats: ScanStats,
    deduper: UrlDeduper,
    rate_limiter: RateLimiter,
) -> None:
    while True:
        try:
            url: str = await asyncio.wait_for(url_queue.get(), timeout=5.0)
        except asyncio.TimeoutError:
            continue

        try:
            if deduper.seen(url):
                url_queue.task_done()
                continue

            body, resp_headers, status = await _fetch(session, url, config, rate_limiter)
            stats.urls_scanned += 1

            if body is None and resp_headers is None:
                stats.urls_errored += 1
                url_queue.task_done()
                continue

            # URL-pattern check (sensitive file paths that returned 200)
            # Pass body so the validator can confirm the response is actually the expected file type.
            if config.check_url_patterns and status == 200:
                for f in scan_url(url, body or ""):
                    if f.severity in config.severity_filter:
                        await result_queue.put(f)
                        _tally(stats, f)

            # Security header analysis (runs on any response with headers)
            if config.check_headers and resp_headers:
                for f in scan_headers(url, resp_headers):
                    if f.severity in config.severity_filter:
                        await result_queue.put(f)
                        _tally(stats, f)

            # Secret / credential scanning in response body
            if config.check_content and body:
                for f in scan_content(url, body):
                    if f.severity in config.severity_filter:
                        await result_queue.put(f)
                        _tally(stats, f)

            # S3 public-bucket check
            if config.check_s3 and is_s3_url(url):
                for f in scan_s3_response(url, body, status):
                    if f.severity in config.severity_filter:
                        await result_queue.put(f)
                        _tally(stats, f)

        except Exception as exc:
            logger.debug("worker %d error on %s: %s", worker_id, url, exc)
            stats.urls_errored += 1
        finally:
            url_queue.task_done()


def _tally(stats: ScanStats, f: Finding) -> None:
    stats.findings_total += 1
    if f.severity == Severity.CRITICAL:
        stats.findings_critical += 1
    elif f.severity == Severity.HIGH:
        stats.findings_high += 1


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

class AveliScanner:
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.url_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self.result_queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
        self.stats = ScanStats()
        self._deduper = UrlDeduper()
        self._rate_limiter = RateLimiter(self.config.requests_per_second)
        self._tasks: list[asyncio.Task] = []
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(
        self,
        enable_ct_logs: bool = True,
        enable_wayback: bool = True,
        enable_s3: bool = True,
        enable_probe: bool = True,
        extra_urls: Optional[list[str]] = None,
    ) -> None:
        # ONE shared session — this is the key fix for the 100% error rate.
        # A single TCPConnector with a sensible limit prevents exhausting
        # the OS file-descriptor table.
        connector = aiohttp.TCPConnector(
            limit=self.config.max_connections,
            ttl_dns_cache=300,
            ssl=False,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={
                "User-Agent": self.config.user_agent,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
            },
        )

        if extra_urls:
            for url in extra_urls:
                await self.url_queue.put(url)

        # Source 1 — crt.sh Certificate Transparency + active path probing
        if enable_ct_logs:
            from .sources.ct_logs import stream_ct_hostnames
            self._tasks.append(
                asyncio.create_task(stream_ct_hostnames(self.url_queue), name="ct-logs")
            )

        # Source 2 — Wayback Machine CDX: historically-exposed sensitive files
        if enable_wayback:
            from .sources.wayback import stream_wayback
            self._tasks.append(
                asyncio.create_task(stream_wayback(self.url_queue), name="wayback")
            )

        # Source 3 — S3 bucket discovery (CT logs + URLScan + Common Crawl)
        if enable_s3:
            from .sources.s3_buckets import stream_s3_buckets
            self._tasks.append(
                asyncio.create_task(stream_s3_buckets(self.url_queue), name="s3-buckets")
            )

        # Baseline seed — probes a rolling list of domains immediately so
        # the queue is never empty while other sources warm up
        if enable_probe:
            from .sources.url_feeds import probe_top_sites
            self._tasks.append(
                asyncio.create_task(probe_top_sites(self.url_queue), name="probe")
            )

        # Worker pool — all share the single session
        for i in range(self.config.workers):
            self._tasks.append(
                asyncio.create_task(
                    scan_worker(
                        worker_id=i,
                        url_queue=self.url_queue,
                        result_queue=self.result_queue,
                        session=self._session,
                        config=self.config,
                        stats=self.stats,
                        deduper=self._deduper,
                        rate_limiter=self._rate_limiter,
                    ),
                    name=f"worker-{i}",
                )
            )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._session:
            await self._session.close()
