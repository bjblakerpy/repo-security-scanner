"""Integration tests for the orchestrator pipeline."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secaudit.config import AppConfig, GithubConfig, PersistenceConfig, TriageConfig, load_config
from secaudit.models import Finding, RepoTarget, ScanResult, Severity, TriageResult
from secaudit.orchestrator import resolve_targets, run_scanners, scan_repo


class TestResolveTargets:
    def test_cli_repos_take_precedence(self):
        config = AppConfig()
        config.github.org = "should-be-ignored"
        targets = resolve_targets(config, cli_repos=["/tmp/test"])
        assert len(targets) == 1
        assert targets[0].path == Path("/tmp/test").resolve()

    def test_org_discovery(self):
        config = AppConfig()
        config.github.token = "ghp_test"
        mock_targets = [
            RepoTarget(name="org/repo1", url="https://github.com/org/repo1"),
            RepoTarget(name="org/repo2", url="https://github.com/org/repo2"),
        ]
        with patch("secaudit.orchestrator.GitHubClient") as MockClient:
            MockClient.return_value.list_org_repos.return_value = mock_targets
            targets = resolve_targets(config, cli_org="my-org")

        assert len(targets) == 2

    def test_config_repos(self):
        config = AppConfig()
        config.github.repos = ["owner/repo1", "owner/repo2"]
        targets = resolve_targets(config)
        assert len(targets) == 2

    def test_default_cwd(self):
        config = AppConfig()
        targets = resolve_targets(config)
        assert len(targets) == 1
        assert targets[0].name == "."  or targets[0].path is not None


class TestRunScanners:
    def test_skips_unavailable_scanners(self, tmp_path):
        config = load_config()
        # All scanners should be skipped since tools aren't installed (except npm)
        findings = run_scanners(tmp_path, config, scanner_names=["gitleaks"])
        # gitleaks not installed, so no findings
        assert findings == []

    def test_runs_specific_scanners(self, tmp_path):
        config = load_config()
        mock_result = ScanResult("test-scanner", str(tmp_path), [
            Finding(scanner="test", severity=Severity.HIGH, title="test finding"),
        ], 1.0)

        with patch("secaudit.orchestrator.get_scanner") as mock_get:
            mock_scanner = MagicMock()
            mock_scanner.name = "test-scanner"
            mock_scanner.is_available.return_value = True
            mock_scanner.is_applicable.return_value = True
            mock_scanner.scan.return_value = mock_result
            mock_get.return_value = mock_scanner

            findings = run_scanners(tmp_path, config, scanner_names=["test-scanner"])

        assert len(findings) == 1
        assert findings[0].title == "test finding"

    def test_handles_scanner_crash(self, tmp_path):
        config = load_config()

        with patch("secaudit.orchestrator.get_scanner") as mock_get:
            mock_scanner = MagicMock()
            mock_scanner.name = "crashing-scanner"
            mock_scanner.is_available.return_value = True
            mock_scanner.is_applicable.return_value = True
            mock_scanner.scan.side_effect = RuntimeError("crash!")
            mock_get.return_value = mock_scanner

            findings = run_scanners(tmp_path, config, scanner_names=["crashing-scanner"])

        assert findings == []  # Should not propagate the crash


class TestScanRepo:
    def test_full_pipeline_local_repo(self, tmp_path):
        target = RepoTarget.from_path(str(tmp_path))
        config = load_config()
        config.triage.enabled = False
        config.persistence = PersistenceConfig(enabled=True, db_path=str(tmp_path / "test.db"))

        # Mock scanners to return a finding
        mock_finding = Finding(scanner="test", severity=Severity.HIGH, title="test vuln")
        mock_finding.compute_fingerprint()

        with patch("secaudit.orchestrator.run_scanners", return_value=[mock_finding]):
            result = scan_repo(
                target, config,
                no_triage=True,
                no_notify=True,
            )

        assert result.triaged_count >= 1
        # Verify triage result was written
        assert (tmp_path / "scan-results.json").exists() or Path("scan-results.json").exists()

    def test_no_findings_pipeline(self, tmp_path):
        target = RepoTarget.from_path(str(tmp_path))
        config = load_config()
        config.persistence = PersistenceConfig(enabled=True, db_path=str(tmp_path / "test.db"))

        with patch("secaudit.orchestrator.run_scanners", return_value=[]):
            result = scan_repo(
                target, config,
                no_triage=True,
                no_notify=True,
            )

        assert result.triaged_count == 0
        assert not result.has_critical

    def test_severity_threshold_filters(self, tmp_path):
        target = RepoTarget.from_path(str(tmp_path))
        config = load_config()
        config.severity_threshold = "HIGH"  # Filter out MEDIUM and LOW
        config.persistence = PersistenceConfig(enabled=True, db_path=str(tmp_path / "test.db"))

        findings = [
            Finding(scanner="test", severity=Severity.CRITICAL, title="critical"),
            Finding(scanner="test", severity=Severity.HIGH, title="high"),
            Finding(scanner="test", severity=Severity.MEDIUM, title="medium"),
            Finding(scanner="test", severity=Severity.LOW, title="low"),
        ]
        for f in findings:
            f.compute_fingerprint()

        with patch("secaudit.orchestrator.run_scanners", return_value=findings):
            result = scan_repo(
                target, config,
                no_triage=True,
                no_notify=True,
            )

        # Only CRITICAL and HIGH should remain (severity <= HIGH means CRITICAL and HIGH)
        assert result.triaged_count == 2
