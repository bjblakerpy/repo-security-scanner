"""Tests for the deduplication module."""

import pytest

from secaudit.models import Finding, Severity, TriageResult
from secaudit.persistence.dedup import deduplicate_and_persist
from secaudit.persistence.store import FindingStore


@pytest.fixture
def store(tmp_db):
    s = FindingStore(tmp_db)
    yield s
    s.close()


@pytest.fixture
def triage_with_findings():
    findings = [
        Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="Secret A"),
        Finding(scanner="semgrep", severity=Severity.HIGH, title="SQLi B"),
    ]
    for f in findings:
        f.compute_fingerprint()
    return TriageResult(
        summary="2 findings",
        findings={"CRITICAL": [findings[0]], "HIGH": [findings[1]]},
        raw_count=2,
        triaged_count=2,
    )


class TestDeduplication:
    def test_first_run_all_new(self, store, triage_with_findings):
        result = deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)
        assert result.triaged_count == 2
        assert len(result.findings.get("CRITICAL", [])) == 1
        assert len(result.findings.get("HIGH", [])) == 1

    def test_second_run_filters_known(self, store, triage_with_findings):
        # First run
        deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)
        # Second run — same findings
        result = deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)
        assert result.triaged_count == 0  # No new findings

    def test_second_run_reports_all_when_disabled(self, store, triage_with_findings):
        # First run
        deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=False)
        # Second run — same findings, notify_new_only=False
        result = deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=False)
        assert result.triaged_count == 2  # All reported

    def test_new_finding_added(self, store, triage_with_findings):
        # First run
        deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)

        # Second run with a new finding added
        new_finding = Finding(scanner="trivy", severity=Severity.HIGH, title="CVE-2024-NEW")
        new_finding.compute_fingerprint()
        updated_triage = TriageResult(
            summary="3 findings",
            findings={
                "CRITICAL": triage_with_findings.findings["CRITICAL"],
                "HIGH": triage_with_findings.findings["HIGH"] + [new_finding],
            },
            raw_count=3,
            triaged_count=3,
        )
        result = deduplicate_and_persist(updated_triage, "test/repo", store, notify_new_only=True)
        assert result.triaged_count == 1  # Only the new one
        assert result.findings["HIGH"][0].title == "CVE-2024-NEW"

    def test_resolved_findings_marked(self, store, triage_with_findings):
        # First run with 2 findings
        deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)

        # Second run with only 1 finding (one was fixed)
        remaining = TriageResult(
            summary="1 finding",
            findings={"CRITICAL": triage_with_findings.findings["CRITICAL"]},
            raw_count=1,
            triaged_count=1,
        )
        deduplicate_and_persist(remaining, "test/repo", store, notify_new_only=True)

        # Check the database — one should be resolved
        resolved = store.get_findings(repo="test/repo", status="resolved")
        assert len(resolved) == 1
        assert resolved[0]["title"] == "SQLi B"

    def test_suppressed_findings_skipped(self, store, triage_with_findings):
        # Insert and suppress one finding
        critical = triage_with_findings.findings["CRITICAL"][0]
        store.upsert_finding(critical, "test/repo")
        store._conn.execute(
            "UPDATE findings SET status = 'suppressed' WHERE fingerprint = ?",
            (critical.fingerprint,),
        )
        store._conn.commit()

        # Run dedup — suppressed finding should be excluded
        result = deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)
        # The critical was suppressed, the high is new
        assert len(result.findings.get("CRITICAL", [])) == 0
        assert len(result.findings.get("HIGH", [])) == 1

    def test_preserves_summary(self, store, triage_with_findings):
        result = deduplicate_and_persist(triage_with_findings, "test/repo", store, notify_new_only=True)
        assert result.summary == "2 findings"
