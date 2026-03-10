"""Tests for scanner implementations."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from secaudit.models import Severity
from secaudit.scanners.gitleaks import GitleaksScanner
from secaudit.scanners.semgrep import SemgrepScanner
from secaudit.scanners.pip_audit import PipAuditScanner
from secaudit.scanners.npm_audit import NpmAuditScanner
from secaudit.scanners.trivy import TrivyScanner
from secaudit.scanners.checkov import CheckovScanner
from secaudit.scanners.hadolint import HadolintScanner
from secaudit.scanners.licenses import LicenseScanner


class TestGitleaks:
    def test_is_applicable_with_git(self, tmp_repo):
        assert GitleaksScanner().is_applicable(tmp_repo) is True

    def test_is_applicable_without_git(self, tmp_path):
        assert GitleaksScanner().is_applicable(tmp_path) is False

    def test_scan_parses_findings(self, tmp_repo):
        gitleaks_output = json.dumps([{
            "RuleID": "aws-access-key",
            "Description": "AWS Access Key",
            "File": "config.py",
            "StartLine": 10,
        }])

        def mock_run(cmd, cwd, timeout=300):
            # Write the report file
            for i, arg in enumerate(cmd):
                if arg == "--report-path":
                    Path(cmd[i + 1]).write_text(gitleaks_output)
            return 1, "", ""

        with patch("secaudit.scanners.gitleaks.run_command", side_effect=mock_run):
            result = GitleaksScanner().scan(tmp_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert "aws-access-key" in result.findings[0].title
        assert result.findings[0].fingerprint  # Fingerprint should be set


class TestSemgrep:
    def test_scan_parses_results(self, tmp_repo):
        semgrep_output = json.dumps({
            "results": [{
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 5},
                "extra": {
                    "severity": "WARNING",
                    "message": "Detected eval() usage",
                    "fix": "Use ast.literal_eval instead",
                },
            }]
        })

        with patch("secaudit.scanners.semgrep.run_command", return_value=(0, semgrep_output, "")):
            result = SemgrepScanner().scan(tmp_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].file_path == "app.py"
        assert result.findings[0].line == 5


class TestPipAudit:
    def test_is_applicable(self, python_repo):
        assert PipAuditScanner().is_applicable(python_repo) is True

    def test_is_not_applicable(self, tmp_repo):
        assert PipAuditScanner().is_applicable(tmp_repo) is False

    def test_scan_parses_vulns(self, python_repo):
        audit_output = json.dumps({
            "dependencies": [{
                "name": "flask",
                "version": "2.0.0",
                "vulns": [{
                    "id": "CVE-2023-12345",
                    "description": "RCE vulnerability",
                    "fix_versions": ["3.0.0"],
                }],
            }]
        })

        with patch("secaudit.scanners.pip_audit.run_command", return_value=(0, audit_output, "")):
            result = PipAuditScanner().scan(python_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert "CVE-2023-12345" in result.findings[0].title


class TestNpmAudit:
    def test_is_applicable(self, node_repo):
        assert NpmAuditScanner().is_applicable(node_repo) is True

    def test_scan_parses_vulns(self, node_repo):
        audit_output = json.dumps({
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "title": "Prototype Pollution",
                    "via": ["lodash"],
                    "fixAvailable": True,
                }
            }
        })

        with patch("secaudit.scanners.npm_audit.run_command", return_value=(0, audit_output, "")):
            result = NpmAuditScanner().scan(node_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH


class TestTrivy:
    def test_is_applicable(self, docker_repo):
        assert TrivyScanner().is_applicable(docker_repo) is True

    def test_is_not_applicable(self, tmp_repo):
        assert TrivyScanner().is_applicable(tmp_repo) is False

    def test_scan_parses_vulns(self, docker_repo):
        trivy_output = json.dumps({
            "Results": [{
                "Target": "Dockerfile",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-00001",
                    "PkgName": "openssl",
                    "Severity": "CRITICAL",
                    "Title": "Buffer overflow in openssl",
                    "InstalledVersion": "1.1.1",
                    "FixedVersion": "1.1.2",
                }],
            }]
        })

        with patch("secaudit.scanners.trivy.run_command", return_value=(0, trivy_output, "")):
            result = TrivyScanner().scan(docker_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL


class TestCheckov:
    def test_is_applicable_with_tf(self, tmp_repo):
        (tmp_repo / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        assert CheckovScanner().is_applicable(tmp_repo) is True

    def test_is_not_applicable(self, tmp_repo):
        assert CheckovScanner().is_applicable(tmp_repo) is False


class TestHadolint:
    def test_is_applicable(self, docker_repo):
        assert HadolintScanner().is_applicable(docker_repo) is True

    def test_scan_parses_results(self, docker_repo):
        hadolint_output = json.dumps([{
            "code": "DL3006",
            "message": "Always tag the version of an image explicitly",
            "level": "warning",
            "line": 1,
        }])

        with patch("secaudit.scanners.hadolint.run_command", return_value=(0, hadolint_output, "")):
            result = HadolintScanner().scan(docker_repo)

        assert result.ok
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM


class TestLicenses:
    def test_is_applicable(self, python_repo):
        assert LicenseScanner().is_applicable(python_repo) is True
