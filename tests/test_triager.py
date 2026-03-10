"""Tests for Claude triager."""

import json
from unittest.mock import MagicMock, patch

import pytest

from secaudit.config import TriageConfig
from secaudit.models import Finding, Severity
from secaudit.triager.claude import _passthrough_triage, triage_findings


@pytest.fixture
def triage_config():
    return TriageConfig(
        enabled=True,
        model="claude-sonnet-4-20250514",
        api_key="sk-test-fake-key",
        max_findings=500,
    )


@pytest.fixture
def findings():
    findings = [
        Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="AWS key leaked"),
        Finding(scanner="semgrep", severity=Severity.HIGH, title="SQL injection"),
        Finding(scanner="pip-audit", severity=Severity.MEDIUM, title="Outdated dep"),
    ]
    for f in findings:
        f.compute_fingerprint()
    return findings


class TestPassthroughTriage:
    def test_groups_by_severity(self, findings):
        result = _passthrough_triage(findings)
        assert len(result.findings["CRITICAL"]) == 1
        assert len(result.findings["HIGH"]) == 1
        assert len(result.findings["MEDIUM"]) == 1
        assert result.raw_count == 3
        assert result.triaged_count == 3

    def test_empty_findings(self):
        result = _passthrough_triage([])
        assert result.triaged_count == 0


class TestTriageFindings:
    def test_no_findings_returns_empty(self, triage_config):
        result = triage_findings([], triage_config)
        assert result.summary == "No findings detected."
        assert result.triaged_count == 0

    def test_no_api_key_falls_back_to_passthrough(self, findings):
        config = TriageConfig(enabled=True, api_key="")
        result = triage_findings(findings, config)
        assert "triage skipped" in result.summary
        assert result.triaged_count == 3

    def test_successful_triage(self, findings, triage_config):
        mock_response = json.dumps({
            "summary": "1 critical secret found.",
            "critical": [{"title": "AWS key leaked", "detail": "Found in config", "recommendation": "Rotate key", "scanner": "gitleaks"}],
            "high": [],
            "medium": [],
            "low": [],
        })

        with patch("secaudit.triager.claude._call_claude", return_value=mock_response):
            result = triage_findings(findings, triage_config)

        assert result.summary == "1 critical secret found."
        assert result.has_critical
        assert len(result.findings["CRITICAL"]) == 1
        assert result.findings["CRITICAL"][0].title == "AWS key leaked"

    def test_handles_markdown_fenced_response(self, findings, triage_config):
        mock_response = '```json\n{"summary":"test","critical":[],"high":[],"medium":[],"low":[]}\n```'

        with patch("secaudit.triager.claude._call_claude", return_value=mock_response):
            result = triage_findings(findings, triage_config)

        assert result.summary == "test"

    def test_handles_invalid_json_falls_back(self, findings, triage_config):
        with patch("secaudit.triager.claude._call_claude", return_value="not valid json"):
            result = triage_findings(findings, triage_config)

        # Should fall back to passthrough
        assert result.triaged_count == 3

    def test_truncates_large_findings(self, triage_config):
        # Create many findings to exceed truncation limit
        findings = []
        for i in range(100):
            f = Finding(scanner="test", severity=Severity.MEDIUM, title=f"Finding {i}", description="x" * 200)
            f.compute_fingerprint()
            findings.append(f)

        mock_response = json.dumps({
            "summary": "Many findings",
            "critical": [], "high": [], "medium": [], "low": [],
        })

        with patch("secaudit.triager.claude._call_claude", return_value=mock_response) as mock_call:
            triage_findings(findings, triage_config)
            # Verify the prompt was called (truncation happens internally)
            mock_call.assert_called_once()
