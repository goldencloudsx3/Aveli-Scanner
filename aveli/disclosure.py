"""
Responsible disclosure workflow.

For each new finding in the database:
  1. Fetch security.txt for the target domain (RFC 9116 standard paths)
  2. Parse contact details
  3. Generate a structured Markdown disclosure report per domain
  4. Print a summary table

Run via:  aveli disclose --db findings.db --output reports/
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

import aiohttp
from rich.console import Console
from rich.table import Table

logger = logging.getLogger("aveli.disclosure")

_SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]
_CONTACT_RE = re.compile(r"(?im)^Contact:\s*(.+)$")


# ── security.txt ──────────────────────────────────────────────────────────────

async def fetch_security_txt(
    domain: str, session: aiohttp.ClientSession
) -> Optional[str]:
    """
    Try RFC 9116 standard paths for security.txt.
    Returns raw text on success, None if not found or invalid.
    """
    for path in _SECURITY_TXT_PATHS:
        url = f"https://{domain}{path}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "Contact:" in text:
                        return text
        except Exception:
            pass
    return None


def parse_contacts(security_txt: str) -> list[str]:
    """Extract all Contact: values from security.txt content."""
    return [m.group(1).strip() for m in _CONTACT_RE.finditer(security_txt)]


# ── Report generation ─────────────────────────────────────────────────────────

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_report(
    domain: str,
    findings: list[dict],
    security_txt: Optional[str],
) -> str:
    """Return a Markdown disclosure report for one domain."""
    contacts = parse_contacts(security_txt) if security_txt else []
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines: list[str] = [
        f"# Security Disclosure Report — {domain}",
        "",
        f"**Date:** {today}",
        f"**Researcher:** Independent Security Researcher (passive credential exposure monitoring)",
        f"**Findings:** {len(findings)} issue(s)",
        "",
    ]

    # Contact section
    if contacts:
        lines += [
            "## Contact",
            "Disclosure contact(s) identified via `security.txt`:",
            "",
            *[f"- {c}" for c in contacts],
            "",
        ]
    else:
        lines += [
            "## Contact",
            "> **No `security.txt` found.** Please forward this report to your security team.",
            "",
        ]

    lines += [
        "## Executive Summary",
        "",
        "During passive monitoring of publicly served web content, the following",
        "credential exposure issues were identified on your infrastructure.",
        "",
        "**No credentials were used, tested, or stored.**",
        "All findings were identified via standard HTTP GET requests to URLs that",
        "were already publicly accessible. No authentication bypass or exploitation",
        "occurred.",
        "",
        "## Findings",
        "",
    ]

    sorted_findings = sorted(
        findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 9)
    )

    for i, f in enumerate(sorted_findings, 1):
        emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
        cvss = f.get("cvss_score")
        cvss_str = f"{cvss:.1f}/10.0" if cvss is not None else "N/A"
        confidence = int((f.get("confidence") or 0) * 100)
        first_seen = (f.get("first_seen") or "N/A")[:10]  # date only

        lines += [
            f"### Finding {i}: {f['vuln_type']}",
            "",
            f"| Field | Value |",
            f"|---|---|",
            f"| **Severity** | {emoji} {f['severity']} |",
            f"| **CVSS Score** | {cvss_str} |",
            f"| **Category** | {f['category']} |",
            f"| **URL** | `{f['url']}` |",
            f"| **First Seen** | {first_seen} |",
            f"| **Detection Confidence** | {confidence}% |",
            "",
            f"**Description:** {f['description']}",
            "",
            f"**Evidence (redacted):** `{f['evidence']}`",
            "",
            f"**Recommended Remediation:** {f['remediation']}",
            "",
        ]

    lines += [
        "---",
        "",
        "## Methodology",
        "",
        "Findings were identified via:",
        "",
        "- Passive HTTP GET requests to publicly accessible URLs discovered through",
        "  Certificate Transparency logs, Common Crawl, and URLScan.io",
        "- Regex-based pattern matching against HTTP response bodies and headers",
        "- No credentials were used, no systems were accessed beyond public endpoints",
        "- All traffic was read-only with no write or authenticated operations",
        "",
        "## Disclosure Timeline",
        "",
        f"- **{today}** — Initial report sent",
        f"- **90-day window** — Findings will not be published before "
        f"{_add_days(today, 90)} to allow remediation",
        "",
        "Please acknowledge receipt and provide a remediation timeline.",
        "We are happy to verify fixes and provide further technical detail.",
        "",
        "---",
        "_Generated by Aveli Scanner — passive credential exposure research tool_",
    ]

    return "\n".join(lines)


def _add_days(date_str: str, days: int) -> str:
    """Return date_str + N days as YYYY-MM-DD."""
    from datetime import timedelta
    d = datetime.strptime(date_str, "%Y-%m-%d") + timedelta(days=days)
    return d.strftime("%Y-%m-%d")


# ── Main workflow ─────────────────────────────────────────────────────────────

async def run_disclosure(db_path: Path, output_dir: Path) -> None:
    """
    Load all 'new' findings from the DB, generate per-domain Markdown reports,
    and print a summary table.
    """
    from .db import FindingsDB

    console = Console()
    db = FindingsDB(db_path)
    findings = db.get_new_findings()

    if not findings:
        console.print("[yellow]No new findings in database.[/yellow]")
        db.close()
        return

    # Group by domain
    by_domain: dict[str, list[dict]] = {}
    for f in findings:
        domain = urlparse(f["url"]).netloc
        by_domain.setdefault(domain, []).append(f)

    console.print(
        f"\n[bold]Disclosing {len(findings)} finding(s) across "
        f"{len(by_domain)} domain(s)[/bold]\n"
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")

    sec_txt_results: dict[str, Optional[str]] = {}

    async with aiohttp.ClientSession() as session:
        for domain, domain_findings in by_domain.items():
            console.print(
                f"[cyan]{domain}[/cyan] — {len(domain_findings)} finding(s)"
            )
            sec_txt = await fetch_security_txt(domain, session)
            sec_txt_results[domain] = sec_txt

            if sec_txt:
                contacts = parse_contacts(sec_txt)
                console.print(
                    f"  [green]security.txt[/green]: "
                    + (", ".join(contacts) if contacts else "found but no contacts parsed")
                )
            else:
                console.print("  [yellow]No security.txt found[/yellow]")

            report = generate_report(domain, domain_findings, sec_txt)
            safe = re.sub(r"[^\w.\-]", "_", domain)
            report_path = output_dir / f"{safe}_{today}.md"
            report_path.write_text(report, encoding="utf-8")
            console.print(f"  Report: [dim]{report_path}[/dim]")

    # Summary table
    table = Table(title="Disclosure Summary", show_lines=True)
    table.add_column("Domain",      style="cyan",  no_wrap=True)
    table.add_column("Findings",    justify="right")
    table.add_column("security.txt", justify="center")
    table.add_column("CRITICAL",    justify="right", style="bold red")
    table.add_column("HIGH",        justify="right", style="yellow")

    for domain, domain_findings in by_domain.items():
        n_critical = sum(1 for f in domain_findings if f["severity"] == "CRITICAL")
        n_high = sum(1 for f in domain_findings if f["severity"] == "HIGH")
        has_sec = "✓" if sec_txt_results.get(domain) else "✗"
        table.add_row(
            domain,
            str(len(domain_findings)),
            has_sec,
            str(n_critical) if n_critical else "-",
            str(n_high) if n_high else "-",
        )

    console.print()
    console.print(table)
    console.print(f"\n[bold green]Reports written to {output_dir}/[/bold green]")
    db.close()
