"""
Rich terminal reporter.

Renders findings and live stats as a beautiful, colour-coded dashboard
in the terminal using the `rich` library.
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
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule

from ..detectors.secrets import Finding, Severity, VulnCategory
from ..scanner import ScanStats

console = Console()


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold white on red",       "🔴 CRITICAL"),
    Severity.HIGH:     ("bold red",                 "🟠 HIGH    "),
    Severity.MEDIUM:   ("bold yellow",              "🟡 MEDIUM  "),
    Severity.LOW:      ("dim cyan",                 "🔵 LOW     "),
    Severity.INFO:     ("dim",                      "⚪ INFO    "),
}

_CATEGORY_ICON: dict[VulnCategory, str] = {
    VulnCategory.EXPOSED_KEY:    "🔑",
    VulnCategory.EXPOSED_SECRET: "🔐",
    VulnCategory.PRIVATE_KEY:    "🗝 ",
    VulnCategory.CRYPTO_SECRET:  "₿ ",
    VulnCategory.DATABASE_CREDS: "🗄 ",
    VulnCategory.CLOUD_CREDS:    "☁️ ",
    VulnCategory.PAYMENT_KEY:    "💳",
    VulnCategory.OAUTH_TOKEN:    "🔓",
    VulnCategory.JWT_TOKEN:      "🎫",
    VulnCategory.SENSITIVE_FILE: "📄",
    VulnCategory.SECURITY_HEADER:"🛡 ",
    VulnCategory.OPEN_REDIRECT:  "↩ ",
    VulnCategory.INFO_DISCLOSURE:"ℹ️ ",
}


def _severity_text(severity: Severity) -> Text:
    style, label = _SEVERITY_STYLE[severity]
    return Text(label, style=style)


def _truncate(s: str, max_len: int = 70) -> str:
    return s if len(s) <= max_len else s[:max_len - 1] + "…"


# ---------------------------------------------------------------------------
# Finding card
# ---------------------------------------------------------------------------

def render_finding(finding: Finding) -> Panel:
    """Render a single finding as a rich Panel."""
    style, _ = _SEVERITY_STYLE[finding.severity]
    icon = _CATEGORY_ICON.get(finding.category, "⚠ ")
    ts = datetime.now().strftime("%H:%M:%S")

    content = Table.grid(padding=(0, 1))
    content.add_column(style="bold", min_width=14)
    content.add_column()

    content.add_row("URL",         Text(_truncate(finding.url, 90), style="link " + finding.url))
    content.add_row("Type",        f"{icon} {finding.vuln_type}")
    content.add_row("Category",    finding.category.value)
    content.add_row("Evidence",    Text(finding.evidence, style="yellow"))
    content.add_row("Description", Text(_truncate(finding.description, 100), style="dim"))
    content.add_row("Fix",         Text(_truncate(finding.remediation, 100), style="italic green"))
    content.add_row("Confidence",  f"{finding.confidence * 100:.0f}%")
    if finding.cvss_score is not None:
        content.add_row("CVSS",    f"{finding.cvss_score:.1f}/10.0")
    if finding.tags:
        content.add_row("Tags",    " ".join(f"[dim]#{t}[/dim]" for t in finding.tags))

    border_style = "red bold" if finding.severity == Severity.CRITICAL else "yellow"
    return Panel(
        content,
        title=f"[{style}] {_severity_style_label(finding.severity)} [/] [{ts}]",
        border_style=border_style,
        expand=True,
    )


def _severity_style_label(severity: Severity) -> str:
    _, label = _SEVERITY_STYLE[severity]
    return label.strip()


# ---------------------------------------------------------------------------
# Stats header
# ---------------------------------------------------------------------------

def render_stats_bar(stats: ScanStats, queue_size: int) -> Panel:
    elapsed = stats.elapsed
    hrs, rem = divmod(int(elapsed), 3600)
    mins, secs = divmod(rem, 60)

    grid = Table.grid(expand=True, padding=(0, 3))
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")

    grid.add_row(
        Text(f"⏱  {hrs:02d}:{mins:02d}:{secs:02d}", style="bold cyan"),
        Text(f"🔍 {stats.urls_scanned:,} scanned", style="bold white"),
        Text(f"📡 {queue_size:,} queued", style="dim white"),
        Text(f"⚡ {stats.rate:.1f}/s", style="bold green"),
        Text(f"🔴 {stats.findings_critical} CRITICAL", style="bold red"),
        Text(f"🟠 {stats.findings_high} HIGH", style="bold yellow"),
        Text(f"⚠  {stats.findings_total} total findings", style="bold white"),
    )

    return Panel(
        grid,
        title="[bold blue]  AVELI SCANNER — Real-Time Vulnerability Intelligence[/]",
        border_style="blue",
        box=box.DOUBLE_EDGE,
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
            self._fh = output_path.open("a", buffering=1)  # line-buffered

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
# Terminal reporter (main live display)
# ---------------------------------------------------------------------------

class TerminalReporter:
    """
    Consumes findings from an async queue and renders them live in the terminal.
    """

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
        banner = """
[bold red]
    ___         ___  _    ___   ___
   / _ \\       / _ \\| |  |_ _| / __|___ __ _ _ _  _ _  ___ _ _
  | (_) |___  | (_) | |__ | |  \\__ \\ / _/ _` | ' \\| ' \\/ -_) '_|
   \\__,_/ _ \\  \\__\\_\\____|___| |___/ \\__\\__,_|_||_|_||_\\___|_|
        |___/
[/bold red]
[dim]Real-time website vulnerability scanner | CT Logs · Common Crawl · URLScan[/dim]
[dim]Monitors for: Exposed Keys · Crypto Secrets · Payment Creds · Private Keys · DB Creds[/dim]
        """
        console.print(banner)
        console.print(Rule("[dim]Initialising sources…[/dim]"))

    def print_finding(self, finding: Finding) -> None:
        """Print a finding panel to the terminal, skipping known duplicates."""
        if self._db:
            is_new = self._db.insert_or_update(finding)
            if not is_new:
                self._skipped_dupes += 1
                return
        self._finding_count += 1
        self._logger.log(finding)
        console.print(render_finding(finding))

    def print_stats(self) -> None:
        """Print a one-line stats update."""
        console.print(
            render_stats_bar(self._stats, self._url_queue.qsize()),
            highlight=False,
        )

    async def run(self, finding_queue: asyncio.Queue, stats_interval: int = 15) -> None:
        """
        Async loop: consume findings and periodically print stats.
        """
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

        # Final summary
        self._logger.close()
        console.print(Rule("[bold]Scan complete[/bold]"))
        self.print_stats()
        if self._logger.count:
            console.print(f"[green]Findings saved to {self._logger.path}[/green]")
        if self._db and self._skipped_dupes:
            console.print(
                f"[dim]{self._skipped_dupes} duplicate finding(s) suppressed "
                f"(already in database)[/dim]"
            )
