"""Tests for the CLI interface using Click's CliRunner."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from secaudit.cli import main


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.2.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Security scanning tool" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--repo" in result.output
        assert "--org" in result.output
        assert "--no-triage" in result.output

    def test_scanners_command(self, runner):
        result = runner.invoke(main, ["scanners"])
        assert result.exit_code == 0
        assert "gitleaks" in result.output
        assert "semgrep" in result.output
        assert "trivy" in result.output
        assert "checkov" in result.output
        assert "hadolint" in result.output
        assert "licenses" in result.output

    def test_report_help(self, runner):
        result = runner.invoke(main, ["report", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--since" in result.output
        assert "--trend" in result.output

    def test_scan_runs_pipeline(self, runner, tmp_path):
        """Scan command invokes the orchestrator."""
        from secaudit.models import TriageResult

        mock_results = [TriageResult(summary="No findings", findings={}, raw_count=0, triaged_count=0)]

        with patch("secaudit.orchestrator.run", return_value=mock_results) as mock_run:
            result = runner.invoke(main, [
                "scan",
                "--repo", str(tmp_path),
                "--no-triage",
                "--no-notify",
            ])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["no_triage"] is True
        assert call_kwargs.kwargs["no_notify"] is True

    def test_scan_exits_1_on_critical_with_pr(self, runner, tmp_path):
        """PR mode exits 1 when critical findings exist."""
        from secaudit.models import Finding, Severity, TriageResult

        critical_finding = Finding(scanner="test", severity=Severity.CRITICAL, title="Secret")
        critical_finding.compute_fingerprint()
        mock_results = [TriageResult(
            summary="Critical found",
            findings={"CRITICAL": [critical_finding]},
            raw_count=1,
            triaged_count=1,
        )]

        with patch("secaudit.orchestrator.run", return_value=mock_results):
            result = runner.invoke(main, [
                "scan",
                "--repo", str(tmp_path),
                "--no-notify",
                "--no-triage",
                "--pr-number", "42",
            ])

        assert result.exit_code == 1
        assert "CRITICAL" in result.output

    def test_report_command(self, runner, tmp_path):
        """Report command queries the finding store."""
        from secaudit.persistence.store import FindingStore

        db_path = str(tmp_path / "test.db")

        with patch("secaudit.cli.load_config") as mock_config:
            mock_config.return_value.persistence.enabled = True
            mock_config.return_value.persistence.db_path = db_path

            result = runner.invoke(main, ["report", "--config", "nonexistent.yml"])

        assert result.exit_code == 0
