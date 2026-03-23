"""
SQLite-backed findings database.

Provides persistent storage, cross-session deduplication, and disclosure
status tracking for all scan findings.

Schema intentionally kept flat (no ORM) for zero extra dependencies —
sqlite3 is part of the Python standard library.
"""

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .detectors.secrets import Finding, Severity

logger = logging.getLogger("aveli.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL,
    vuln_type     TEXT    NOT NULL,
    category      TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    evidence      TEXT    NOT NULL,
    evidence_hash TEXT    NOT NULL,
    confidence    REAL,
    cvss_score    REAL,
    description   TEXT,
    remediation   TEXT,
    tags          TEXT,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    session_count INTEGER NOT NULL DEFAULT 1,
    disclosed_at  TEXT,
    status        TEXT    NOT NULL DEFAULT 'new'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings (url, vuln_type, evidence_hash);

CREATE INDEX IF NOT EXISTS idx_findings_status
    ON findings (status);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);
"""

_SEVERITY_RANK = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END"


def _evidence_hash(url: str, vuln_type: str, evidence: str) -> str:
    """16-char stable dedup key for a finding."""
    key = f"{url}\x00{vuln_type}\x00{evidence}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FindingsDB:
    """
    Thread-safe SQLite findings store.

    All methods are synchronous. sqlite3 with WAL mode is fast enough for
    the scan throughput; no run_in_executor wrapping needed.
    """

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Findings DB: %s", db_path)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_or_update(self, finding: Finding) -> bool:
        """
        Insert a new finding or bump session_count if already recorded.
        Returns True if this is a NEW finding (not previously seen).
        """
        h = _evidence_hash(finding.url, finding.vuln_type, finding.evidence)
        now = _now()
        try:
            self._conn.execute(
                """
                INSERT INTO findings
                    (url, vuln_type, category, severity, evidence, evidence_hash,
                     confidence, cvss_score, description, remediation, tags,
                     first_seen, last_seen, session_count, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,'new')
                """,
                (
                    finding.url,
                    finding.vuln_type,
                    finding.category.value,
                    finding.severity.value,
                    finding.evidence,
                    h,
                    finding.confidence,
                    finding.cvss_score,
                    finding.description,
                    finding.remediation,
                    json.dumps(finding.tags),
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return True  # new
        except sqlite3.IntegrityError:
            self._conn.execute(
                """
                UPDATE findings
                SET last_seen = ?, session_count = session_count + 1
                WHERE url = ? AND vuln_type = ? AND evidence_hash = ?
                """,
                (now, finding.url, finding.vuln_type, h),
            )
            self._conn.commit()
            return False  # duplicate

    def mark_disclosed(self, finding_id: int) -> None:
        self._conn.execute(
            "UPDATE findings SET status='disclosed', disclosed_at=? WHERE id=?",
            (_now(), finding_id),
        )
        self._conn.commit()

    def mark_false_positive(self, finding_id: int) -> None:
        self._conn.execute(
            "UPDATE findings SET status='false_positive' WHERE id=?",
            (finding_id,),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_new_findings(self) -> list[dict]:
        """All findings with status='new', highest severity first."""
        cur = self._conn.execute(
            f"SELECT * FROM findings WHERE status='new' ORDER BY {_SEVERITY_RANK}, first_seen DESC"
        )
        return [dict(row) for row in cur.fetchall()]

    def summary(self) -> dict:
        cur = self._conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status='new'          THEN 1 ELSE 0 END) AS new,
                SUM(CASE WHEN status='disclosed'    THEN 1 ELSE 0 END) AS disclosed,
                SUM(CASE WHEN status='false_positive' THEN 1 ELSE 0 END) AS false_positive,
                SUM(CASE WHEN severity='CRITICAL'   THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity='HIGH'       THEN 1 ELSE 0 END) AS high
            FROM findings
            """
        )
        return dict(cur.fetchone())

    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()
