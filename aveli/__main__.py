"""
Aveli Scanner CLI entry point.

Usage:
    aveli scan [OPTIONS]         run the vulnerability scanner
    aveli disclose [OPTIONS]     generate disclosure reports from the findings DB

Examples:
    aveli scan                                  # run with all defaults
    aveli scan --workers 8 --rps 10             # conservative (Mac default)
    aveli scan --min-severity critical          # only CRITICAL findings
    aveli scan --urls urls.txt                  # scan a custom URL list
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


@click.group()
def cli() -> None:
    """Aveli Scanner — Real-Time Vulnerability Intelligence"""


@cli.command("scan")
@click.option("--workers", "-w",     default=8,    show_default=True,
              help="Concurrent scan workers. Keep ≤10 on Mac without ulimit changes.")
@click.option("--rps",               default=10.0, show_default=True,
              help="Max requests per second.")
@click.option("--min-severity", "-s",
              default="high",
              type=click.Choice(["critical", "high", "medium", "low", "info"],
                                case_sensitive=False),
              show_default=True,
              help="Minimum severity to report.")
@click.option("--output", "-o",      default=None, help="JSONL file for findings.")
@click.option("--db",                default=None, help="SQLite DB for persistence & dedup.")
@click.option("--config", "-c",      default=None, help="Path to aveli.yml config file.")
@click.option("--urls",              default=None,
              help="Text file with one URL per line to seed the queue.")
@click.option("--no-ct",             is_flag=True, help="Disable crt.sh CT log source.")
@click.option("--no-wayback",        is_flag=True, help="Disable Wayback Machine CDX source.")
@click.option("--no-s3",             is_flag=True, help="Disable S3 bucket discovery.")
@click.option("--no-probe",          is_flag=True, help="Disable baseline domain probe.")
@click.option("--no-headers",        is_flag=True, help="Skip HTTP security header checks.")
@click.option("--no-content",        is_flag=True, help="Skip response body secret scanning.")
@click.option("--timeout",           default=10,   show_default=True,
              help="HTTP request timeout (seconds).")
@click.option("--verbose", "-v",     is_flag=True, help="Enable verbose debug logging.")
@click.option("--stats-interval",    default=15,   show_default=True,
              help="Stats print interval (seconds).")
def scan_cmd(
    workers: int,
    rps: float,
    min_severity: str,
    output: Optional[str],
    db: Optional[str],
    config: Optional[str],
    urls: Optional[str],
    no_ct: bool,
    no_wayback: bool,
    no_s3: bool,
    no_probe: bool,
    no_headers: bool,
    no_content: bool,
    timeout: int,
    verbose: bool,
    stats_interval: int,
) -> None:
    """
    Scan the internet for exposed credentials, secrets, and misconfigurations.

    \b
    Three focused sources:
      1. crt.sh CT logs   — fresh domains probed with 29 sensitive paths
      2. Wayback Machine  — historically-exposed files re-probed live
      3. S3 discovery     — publicly listable buckets via CT + URLScan

    \b
    Detects: API keys · crypto secrets · payment creds · private keys
             DB credentials · missing HSTS/CSP · public S3 buckets
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
    scan_config.check_s3 = not no_s3

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
        p = Path(urls)
        if p.exists():
            extra_urls = [ln.strip() for ln in p.read_text().splitlines()
                          if ln.strip().startswith("http")]
            click.echo(f"Loaded {len(extra_urls)} URLs from {urls}")
        else:
            click.echo(f"[warn] URL file not found: {urls}", err=True)

    asyncio.run(
        _run(
            scan_config=scan_config,
            enable_ct=not no_ct,
            enable_wayback=not no_wayback,
            enable_s3=not no_s3,
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
    enable_wayback: bool,
    enable_s3: bool,
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
        enable_wayback=enable_wayback,
        enable_s3=enable_s3,
        enable_probe=enable_probe,
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
            pass

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
                f"\nSession — total: {summary['total']}  "
                f"new: {summary['new']}  "
                f"critical: {summary['critical']}  high: {summary['high']}"
            )


@cli.command("disclose")
@click.option("--db", "-d", required=True, help="Findings SQLite database path.")
@click.option("--output", "-o", default="reports", show_default=True,
              help="Directory to write Markdown disclosure reports.")
def disclose_cmd(db: str, output: str) -> None:
    """Generate Markdown disclosure reports for new findings."""
    from .disclosure import run_disclosure
    asyncio.run(run_disclosure(Path(db), Path(output)))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
