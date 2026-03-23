"""
Aveli Scanner CLI entry point.

Usage:
    aveli scan [OPTIONS]         run the website vulnerability scanner
    aveli disclose [OPTIONS]     generate disclosure reports from the findings DB

Examples:
    aveli scan                                         # run with all defaults
    aveli scan --workers 40 --rps 50                   # more aggressive
    aveli scan --min-severity critical                 # only CRITICAL findings
    aveli scan --no-ct --no-cc --urls urls.txt         # scan a custom URL list
    aveli scan --output findings.jsonl --db findings.db
    aveli disclose --db findings.db --output reports/
"""

import asyncio
import logging
import signal
from pathlib import Path
from typing import Optional

import click

from .scanner import AveliScanner, ScannerConfig
from .detectors.secrets import Severity
from .reporters.terminal import TerminalReporter
from .config import load_config


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """
    \b
    ╔══════════════════════════════════════════════════════════╗
    ║  AVELI SCANNER  —  Real-Time Vulnerability Intelligence  ║
    ╚══════════════════════════════════════════════════════════╝

    Commands:
      scan      Monitor the internet for exposed credentials & misconfigs
      disclose  Generate Markdown disclosure reports from the findings DB
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.option("--workers", "-w",  default=20,   show_default=True, help="Concurrent scan workers.")
@click.option("--rps",            default=20.0,  show_default=True, help="Max requests per second.")
@click.option(
    "--min-severity", "-s",
    default="high",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option("--output", "-o",   default=None,  help="JSONL file to append findings to.")
@click.option("--db",             default=None,  help="SQLite DB path for persistent storage & dedup.")
@click.option("--config", "-c",   default=None,  help="Path to aveli.yml config file.")
@click.option("--urls",           default=None,  help="Text file with one URL per line to seed the queue.")
@click.option("--no-ct",          is_flag=True,  help="Disable Certificate Transparency log source.")
@click.option("--no-cc",          is_flag=True,  help="Disable Common Crawl source.")
@click.option("--no-urlscan",     is_flag=True,  help="Disable URLScan.io source.")
@click.option("--openphish",      is_flag=True,  help="Enable OpenPhish feed (off by default).")
@click.option("--no-probe",       is_flag=True,  help="Disable top-sites sensitive-path probe.")
@click.option("--no-headers",     is_flag=True,  help="Skip HTTP security header checks.")
@click.option("--no-content",     is_flag=True,  help="Skip response body secret scanning.")
@click.option("--timeout",        default=12,    show_default=True, help="HTTP request timeout (seconds).")
@click.option("--verbose", "-v",  is_flag=True,  help="Enable verbose debug logging.")
@click.option("--stats-interval", default=15,    show_default=True, help="Stats print interval (seconds).")
def scan_cmd(
    workers: int,
    rps: float,
    min_severity: str,
    output: Optional[str],
    db: Optional[str],
    config: Optional[str],
    urls: Optional[str],
    no_ct: bool,
    no_cc: bool,
    no_urlscan: bool,
    openphish: bool,
    no_probe: bool,
    no_headers: bool,
    no_content: bool,
    timeout: int,
    verbose: bool,
    stats_interval: int,
) -> None:
    """
    Monitor internet-wide website changes for critical security vulnerabilities.

    \b
    Detects: exposed API keys · crypto secrets · payment credentials
             private keys · database URIs · JWT tokens · misconfigs

    \b
    Sources: Certificate Transparency logs · Common Crawl CDX
             URLScan.io · OpenPhish · Top-site path probing
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    cfg_path = Path(config) if config else Path("aveli.yml")
    scan_config = load_config(cfg_path if cfg_path.exists() else None)

    scan_config.workers = workers
    scan_config.requests_per_second = rps
    scan_config.request_timeout = timeout
    scan_config.check_headers = not no_headers
    scan_config.check_content = not no_content

    severity_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }
    levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    min_sev = severity_map[min_severity.lower()]
    scan_config.min_severity = min_sev
    scan_config.severity_filter = set(levels[: levels.index(min_sev) + 1])

    extra_urls: list[str] = []
    if urls:
        urls_path = Path(urls)
        if urls_path.exists():
            with open(urls_path) as fh:
                extra_urls = [ln.strip() for ln in fh if ln.strip().startswith("http")]
            click.echo(f"Loaded {len(extra_urls)} URLs from {urls}")
        else:
            click.echo(f"[warn] URLs file not found: {urls}", err=True)

    asyncio.run(
        _run(
            scan_config=scan_config,
            enable_ct=not no_ct,
            enable_cc=not no_cc,
            enable_urlscan=not no_urlscan,
            enable_openphish=openphish,
            enable_probe=not no_probe,
            extra_urls=extra_urls,
            output_path=Path(output) if output else None,
            db_path=Path(db) if db else None,
            stats_interval=stats_interval,
        )
    )


async def _run(
    scan_config: ScannerConfig,
    enable_ct: bool,
    enable_cc: bool,
    enable_urlscan: bool,
    enable_openphish: bool,
    enable_probe: bool,
    extra_urls: list[str],
    output_path: Optional[Path],
    db_path: Optional[Path],
    stats_interval: int,
) -> None:
    from .db import FindingsDB

    db = FindingsDB(db_path) if db_path else None

    scanner = AveliScanner(config=scan_config)
    reporter = TerminalReporter(
        stats=scanner.stats,
        url_queue_ref=scanner.url_queue,
        output_file=output_path,
        db=db,
    )

    await scanner.start(
        enable_ct_logs=enable_ct,
        enable_common_crawl=enable_cc,
        enable_urlscan=enable_urlscan,
        enable_openphish=enable_openphish,
        enable_top_sites_probe=enable_probe,
        extra_urls=extra_urls,
    )

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _handle_signal():
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass  # Windows

    reporter_task = asyncio.create_task(
        reporter.run(scanner.result_queue, stats_interval=stats_interval)
    )

    try:
        await shutdown_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        reporter_task.cancel()
        await scanner.stop()
        if db:
            summary = db.summary()
            db.close()
            click.echo(
                f"\nDB summary — total: {summary['total']}  "
                f"new: {summary['new']}  "
                f"disclosed: {summary['disclosed']}  "
                f"critical: {summary['critical']}  high: {summary['high']}"
            )


# ---------------------------------------------------------------------------
# disclose
# ---------------------------------------------------------------------------

@cli.command("disclose")
@click.option(
    "--db", "-d",
    required=True,
    help="Path to the findings SQLite database (findings.db).",
)
@click.option(
    "--output", "-o",
    default="reports",
    show_default=True,
    help="Directory to write Markdown disclosure reports into.",
)
def disclose_cmd(db: str, output: str) -> None:
    """
    Generate Markdown disclosure reports for all new findings in the database.

    \b
    For each domain:
      · Checks /.well-known/security.txt and /security.txt
      · Parses Contact: addresses
      · Writes a ready-to-send Markdown report with 90-day embargo note

    \b
    Example:
      aveli disclose --db findings.db --output reports/
    """
    from .disclosure import run_disclosure

    asyncio.run(run_disclosure(Path(db), Path(output)))


# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
