"""
Terminal reporter — clean, informative live dashboard.

Shows:
  - Live stats bar (scanned, queued, rate, findings by severity)
  - Error rate so you can see if sources are working
  - Each finding as a clear, readable panel
  - Source status log every stats interval
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..db import FindingsDB

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule
from rich.columns import Columns

from ..detectors.secrets import Finding, Severity, VulnCategory
from ..scanner import ScanStats

console = Console()


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold white on red",   "CRITICAL"),
    Severity.HIGH:     ("bold red",             "HIGH    "),
    Severity.MEDIUM:   ("bold yellow",          "MEDIUM  "),
    Severity.LOW:      ("dim cyan",             "LOW     "),
    Severity.INFO:     ("dim",                  "INFO    "),
}

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "[bold white on red] CRITICAL [/]",
    Severity.HIGH:     "[bold red] HIGH [/]",
    Severity.MEDIUM:   "[bold yellow] MEDIUM [/]",
    Severity.LOW:      "[cyan] LOW [/]",
    Severity.INFO:     "[dim] INFO [/]",
}

_CATEGORY_ICON: dict[VulnCategory, str] = {
    VulnCategory.EXPOSED_KEY:        "🔑",
    VulnCategory.EXPOSED_SECRET:     "🔐",
    VulnCategory.PRIVATE_KEY:        "🗝 ",
    VulnCategory.CRYPTO_SECRET:      "₿ ",
    VulnCategory.DATABASE_CREDS:     "🗄 ",
    VulnCategory.CLOUD_CREDS:        "☁️ ",
    VulnCategory.PAYMENT_KEY:        "💳",
    VulnCategory.OAUTH_TOKEN:        "🔓",
    VulnCategory.JWT_TOKEN:          "🎫",
    VulnCategory.SENSITIVE_FILE:     "📄",
    VulnCategory.SECURITY_HEADER:    "🛡 ",
    VulnCategory.OPEN_REDIRECT:      "↩ ",
    VulnCategory.INFO_DISCLOSURE:    "ℹ️ ",
    VulnCategory.S3_MISCONFIGURATION:"🪣 ",
}


def _truncate(s: str, max_len: int = 80) -> str:
    return s if len(s) <= max_len else s[:max_len - 1] + "…"


# ---------------------------------------------------------------------------
# Finding panel
# ---------------------------------------------------------------------------

def render_finding(finding: Finding, count: int) -> Panel:
    icon = _CATEGORY_ICON.get(finding.category, "⚠ ")
    ts = datetime.now().strftime("%H:%M:%S")
    badge = _SEVERITY_BADGE[finding.severity]
    border = "red bold" if finding.severity == Severity.CRITICAL else (
        "yellow" if finding.severity == Severity.HIGH else "cyan"
    )

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold dim", min_width=12)
    grid.add_column()

    grid.add_row("URL",         Text(_truncate(finding.url, 90), style="bright_cyan underline"))
    grid.add_row("Type",        f"{icon} {finding.vuln_type}")
    grid.add_row("Evidence",    Text(finding.evidence, style="yellow"))
    grid.add_row("Fix",         Text(_truncate(finding.remediation, 90), style="green"))
    if finding.cvss_score is not None:
        grid.add_row("CVSS",    f"{finding.cvss_score:.1f} / 10.0")
    grid.add_row("Confidence",  f"{finding.confidence * 100:.0f}%")
    if finding.tags:
        grid.add_row("Tags",    " ".join(f"#{t}" for t in finding.tags))

    return Panel(
        grid,
        title=f"[dim]#{count}[/dim]  {badge}  [dim]{ts}[/dim]",
        border_style=border,
        expand=True,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Stats bar
# ---------------------------------------------------------------------------

def render_stats(stats: ScanStats, queue_size: int) -> Panel:
    elapsed = stats.elapsed
    hrs, rem = divmod(int(elapsed), 3600)
    mins, secs = divmod(rem, 60)

    error_rate = (
        f"{stats.urls_errored / stats.urls_scanned * 100:.0f}% err"
        if stats.urls_scanned > 0 else "—"
    )

    grid = Table.grid(expand=True, padding=(0, 2))
    for _ in range(8):
        grid.add_column(justify="center")

    grid.add_row(
        Text(f"⏱  {hrs:02d}:{mins:02d}:{secs:02d}", style="bold cyan"),
        Text(f"🔍  {stats.urls_scanned:,}  scanned", style="bold white"),
        Text(f"📡  {queue_size:,}  queued", style="white"),
        Text(f"⚡  {stats.rate:.1f}/s", style="bold green"),
        Text(f"❌  {error_rate}", style="dim red"),
        Text(f"🔴  {stats.findings_critical}  CRIT", style="bold red"),
        Text(f"🟠  {stats.findings_high}  HIGH", style="bold yellow"),
        Text(f"⚠   {stats.findings_total}  total", style="bold white"),
    )

    return Panel(
        grid,
        title="[bold blue]AVELI SCANNER — Real-Time Vulnerability Intelligence[/bold blue]",
        border_style="blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Source status
# ---------------------------------------------------------------------------

def print_source_status(queue_size: int, stats: ScanStats) -> None:
    """Print a one-line source health summary."""
    if stats.urls_scanned == 0:
        console.print(
            "[dim yellow]⏳ Waiting for sources to deliver URLs…  "
            "(crt.sh polls every 60s, Wayback every 30min, Tranco every 10min)[/dim yellow]"
        )
    elif queue_size == 0:
        console.print(
            "[dim yellow]⚠  Queue empty — sources may be sleeping. "
            f"Scanned so far: {stats.urls_scanned:,}  Errors: {stats.urls_errored:,}[/dim yellow]"
        )
    else:
        console.print(
            f"[dim green]✓  {queue_size:,} URLs queued — workers active[/dim green]"
        )


# ---------------------------------------------------------------------------
# JSON file logger
# ---------------------------------------------------------------------------

class FindingLogger:
    def __init__(self, output_path: Optional[Path] = None):
        self._path = output_path
        self._count = 0
        self._fh = None
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = output_path.open("a", buffering=1)

    def log(self, finding: Finding) -> None:
        if not self._fh:
            return
        self._fh.write(json.dumps(finding.to_dict()) + "\n")
        self._count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.flush()
            self._fh.close()
            self._fh = None

    @property
    def count(self) -> int:
        return self._count

    @property
    def path(self) -> Optional[Path]:
        return self._path


# ---------------------------------------------------------------------------
# Terminal reporter
# ---------------------------------------------------------------------------

class TerminalReporter:
    def __init__(
        self,
        stats: ScanStats,
        url_queue_ref,
        output_file: Optional[Path] = None,
        db: Optional["FindingsDB"] = None,
    ):
        self._stats = stats
        self._url_queue = url_queue_ref
        self._logger = FindingLogger(output_file)
        self._finding_count = 0
        self._db = db
        self._skipped_dupes = 0

    def print_banner(self) -> None:
        console.print()
        console.print(
            "[bold red]"
            "  ▄▄▄·  ▌ ▐· ▄▄▄ .▄▄▌  ▪  \n"
            "  ▐█ ▀█ ▪█·█▌ ▀▄.▀·██•  ██ \n"
            "  ▄█▀▀█ ▐█▐█• ▐▀▀▪▄██▪  ▐█·\n"
            "  ▐█ ▪▐▌ ███  ▐█▄▄▌▐█▌▐▌▐█▌\n"
            "   ▀  ▀ . ▀    ▀▀▀ .▀▀▀ ▀▀▀"
            "[/bold red]"
        )
        console.print(
            "  [bold white]S C A N N E R[/bold white]"
            "  [dim]─  Real-Time Internet Vulnerability Intelligence[/dim]"
        )
        console.print()

        info = Table.grid(padding=(0, 3))
        info.add_column(style="bold dim", min_width=12)
        info.add_column()
        info.add_row(
            "SOURCES",
            "[cyan]CT Logs (crt.sh)[/cyan]  ·  "
            "[cyan]Wayback Machine[/cyan]  ·  "
            "[cyan]URLScan.io[/cyan]  ·  "
            "[cyan]S3 Buckets[/cyan]  ·  "
            "[cyan]Active Domain Probing[/cyan]",
        )
        info.add_row(
            "DETECTS",
            "[yellow]Exposed API Keys[/yellow]  ·  "
            "[yellow]Crypto Secrets[/yellow]  ·  "
            "[yellow]Payment Credentials[/yellow]  ·  "
            "[yellow]Private Keys[/yellow]  ·  "
            "[yellow]DB Credentials[/yellow]  ·  "
            "[yellow]Missing Security Headers[/yellow]  ·  "
            "[yellow]Public S3 Buckets[/yellow]",
        )
        info.add_row(
            "SEVERITY",
            "[bold white on red] CRITICAL [/]  "
            "[bold red] HIGH [/]  "
            "[bold yellow] MEDIUM [/]  "
            "[cyan] LOW [/]",
        )
        console.print(Panel(info, border_style="blue", padding=(0, 2)))
        console.print(
            "[dim yellow]  ⏳  Queue starts empty — crt.sh polls every 60s, "
            "Wayback Machine loads immediately, active probing begins now.[/dim yellow]\n"
        )

    def print_finding(self, finding: Finding) -> None:
        if self._db:
            is_new = self._db.insert_or_update(finding)
            if not is_new:
                self._skipped_dupes += 1
                return
        self._finding_count += 1
        self._logger.log(finding)
        console.print(render_finding(finding, self._finding_count))

    def print_stats(self) -> None:
        console.print(render_stats(self._stats, self._url_queue.qsize()), highlight=False)
        print_source_status(self._url_queue.qsize(), self._stats)

    async def run(self, finding_queue: asyncio.Queue, stats_interval: int = 15) -> None:
        self.print_banner()
        last_stats = time.time()

        while True:
            try:
                finding: Finding = await asyncio.wait_for(finding_queue.get(), timeout=1.0)
                self.print_finding(finding)
                finding_queue.task_done()
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                break

            if time.time() - last_stats >= stats_interval:
                self.print_stats()
                last_stats = time.time()

        self._logger.close()
        console.print(Rule("[bold]Scan complete[/bold]"))
        self.print_stats()
        if self._logger.count:
            console.print(f"[green]✓ Findings saved to {self._logger.path}[/green]")
        if self._db and self._skipped_dupes:
            console.print(f"[dim]{self._skipped_dupes} duplicate(s) suppressed[/dim]")
