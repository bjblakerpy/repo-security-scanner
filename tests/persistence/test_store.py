"""Tests for the SQLite finding store."""

import pytest

from secaudit.models import Finding, Severity
from secaudit.persistence.store import FindingStore


@pytest.fixture
def store(tmp_db):
    s = FindingStore(tmp_db)
    yield s
    s.close()


@pytest.fixture
def finding():
    f = Finding(
        scanner="gitleaks",
        severity=Severity.CRITICAL,
        title="AWS key leaked",
        description="Found in config.py",
        file_path="config.py",
        line=10,
        recommendation="Rotate immediately",
    )
    f.compute_fingerprint()
    return f


class TestFindingStore:
    def test_upsert_new_finding(self, store, finding):
        is_new = store.upsert_finding(finding, "test/repo")
        assert is_new is True

    def test_upsert_existing_finding(self, store, finding):
        store.upsert_finding(finding, "test/repo")
        is_new = store.upsert_finding(finding, "test/repo")
        assert is_new is False

    def test_get_findings(self, store, finding):
        store.upsert_finding(finding, "test/repo")
        results = store.get_findings(repo="test/repo")
        assert len(results) == 1
        assert results[0]["title"] == "AWS key leaked"
        assert results[0]["severity"] == "CRITICAL"

    def test_mark_resolved(self, store, finding):
        store.upsert_finding(finding, "test/repo")
        resolved = store.mark_resolved("test/repo", set())  # No active fingerprints
        assert resolved == 1

        results = store.get_findings(repo="test/repo", status="resolved")
        assert len(results) == 1

    def test_get_new_findings(self, store, finding):
        # First time: finding is new
        new = store.get_new_findings([finding], "test/repo")
        assert len(new) == 1

        # After inserting: not new
        store.upsert_finding(finding, "test/repo")
        new = store.get_new_findings([finding], "test/repo")
        assert len(new) == 0

    def test_record_scan(self, store):
        store.record_scan("test/repo", 15.5, 3, "gitleaks,semgrep")
        history = store.get_scan_history(repo="test/repo")
        assert len(history) == 1
        assert history[0]["finding_count"] == 3

    def test_suppressed_finding(self, store, finding):
        store.upsert_finding(finding, "test/repo")

        # Manually suppress
        store._conn.execute(
            "UPDATE findings SET status = 'suppressed' WHERE fingerprint = ?",
            (finding.fingerprint,),
        )
        store._conn.commit()

        assert store.is_suppressed(finding.fingerprint, "test/repo") is True

    def test_severity_ordering(self, store):
        """Findings should be ordered by severity (critical first)."""
        for sev, title in [
            (Severity.LOW, "Low issue"),
            (Severity.CRITICAL, "Critical issue"),
            (Severity.MEDIUM, "Medium issue"),
        ]:
            f = Finding(scanner="test", severity=sev, title=title)
            f.compute_fingerprint()
            store.upsert_finding(f, "test/repo")

        results = store.get_findings(repo="test/repo")
        assert results[0]["severity"] == "CRITICAL"
        assert results[1]["severity"] == "MEDIUM"
        assert results[2]["severity"] == "LOW"
