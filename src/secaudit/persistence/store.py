"""SQLite-backed finding store for cross-run deduplication and trend tracking."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from secaudit.models import Finding, Severity

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    scanner TEXT NOT NULL,
    repo TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    file_path TEXT,
    line INTEGER,
    recommendation TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    UNIQUE(fingerprint, repo)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    duration_seconds REAL DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    scanners TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo);
"""


class FindingStore:
    """SQLite store for persisting and querying findings across runs."""

    def __init__(self, db_path: str = "~/.secaudit/findings.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def upsert_finding(self, finding: Finding, repo: str) -> bool:
        """Insert or update a finding. Returns True if this is a new finding."""
        now = datetime.now(timezone.utc).isoformat()

        # Check if exists
        row = self._conn.execute(
            "SELECT id, status FROM findings WHERE fingerprint = ? AND repo = ?",
            (finding.fingerprint, repo),
        ).fetchone()

        if row:
            # Update last_seen and reopen if previously resolved
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, severity = ?, title = ?, "
                "description = ?, recommendation = ?, status = CASE WHEN status = 'resolved' THEN 'reopened' ELSE status END "
                "WHERE id = ?",
                (now, finding.severity.value, finding.title, finding.description, finding.recommendation, row["id"]),
            )
            self._conn.commit()
            return False
        else:
            # Insert new finding
            self._conn.execute(
                "INSERT INTO findings (fingerprint, scanner, repo, severity, title, description, "
                "file_path, line, recommendation, first_seen, last_seen, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
                (
                    finding.fingerprint,
                    finding.scanner,
                    repo,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.file_path,
                    finding.line,
                    finding.recommendation,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return True

    def mark_resolved(self, repo: str, active_fingerprints: set[str]) -> int:
        """Mark findings not in active_fingerprints as resolved. Returns count."""
        if not active_fingerprints:
            cursor = self._conn.execute(
                "UPDATE findings SET status = 'resolved' WHERE repo = ? AND status = 'open'",
                (repo,),
            )
        else:
            placeholders = ",".join("?" * len(active_fingerprints))
            cursor = self._conn.execute(
                f"UPDATE findings SET status = 'resolved' "
                f"WHERE repo = ? AND status = 'open' AND fingerprint NOT IN ({placeholders})",
                (repo, *active_fingerprints),
            )
        self._conn.commit()
        return cursor.rowcount

    def get_new_findings(self, findings: list[Finding], repo: str) -> list[Finding]:
        """Filter to only findings that are new (not previously seen)."""
        new = []
        for f in findings:
            row = self._conn.execute(
                "SELECT id FROM findings WHERE fingerprint = ? AND repo = ?",
                (f.fingerprint, repo),
            ).fetchone()
            if not row:
                new.append(f)
        return new

    def record_scan(self, repo: str, duration: float, finding_count: int, scanners: str) -> None:
        """Record a scan run for trend tracking."""
        self._conn.execute(
            "INSERT INTO scans (repo, timestamp, duration_seconds, finding_count, scanners) VALUES (?, ?, ?, ?, ?)",
            (repo, datetime.now(timezone.utc).isoformat(), duration, finding_count, scanners),
        )
        self._conn.commit()

    def get_findings(
        self,
        repo: str | None = None,
        severity: str | None = None,
        status: str = "open",
        since: str | None = None,
    ) -> list[dict]:
        """Query findings with optional filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []

        if repo:
            query += " AND repo = ?"
            params.append(repo)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status)
        if since:
            query += " AND first_seen >= ?"
            params.append(since)

        query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_scan_history(self, repo: str | None = None, limit: int = 50) -> list[dict]:
        """Get recent scan history for trend tracking."""
        query = "SELECT * FROM scans"
        params: list = []
        if repo:
            query += " WHERE repo = ?"
            params.append(repo)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def is_suppressed(self, fingerprint: str, repo: str) -> bool:
        """Check if a finding is suppressed (false positive)."""
        row = self._conn.execute(
            "SELECT status FROM findings WHERE fingerprint = ? AND repo = ?",
            (fingerprint, repo),
        ).fetchone()
        return row is not None and row["status"] == "suppressed"
