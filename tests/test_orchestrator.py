"""Tests for the orchestrator."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secaudit.config import load_config
from secaudit.models import Finding, RepoTarget, Severity


class TestRepoTarget:
    def test_from_path(self, tmp_path):
        target = RepoTarget.from_path(str(tmp_path))
        assert target.path == tmp_path
        assert target.name == tmp_path.name

    def test_from_url(self):
        target = RepoTarget.from_url("https://github.com/owner/repo.git")
        assert target.owner == "owner"
        assert target.repo_name == "repo"
        assert target.name == "owner/repo"

    def test_from_spec_url(self):
        target = RepoTarget.from_spec("https://github.com/owner/repo")
        assert target.owner == "owner"
        assert target.repo_name == "repo"

    def test_from_spec_shorthand(self):
        target = RepoTarget.from_spec("owner/repo")
        assert target.url == "https://github.com/owner/repo"

    def test_from_spec_local(self, tmp_path):
        target = RepoTarget.from_spec(str(tmp_path))
        assert target.path == tmp_path


class TestFinding:
    def test_fingerprint_is_stable(self):
        f1 = Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="key leak", file_path="a.py", line=10)
        f2 = Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="key leak", file_path="a.py", line=10)
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs(self):
        f1 = Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="key leak", file_path="a.py", line=10)
        f2 = Finding(scanner="gitleaks", severity=Severity.CRITICAL, title="key leak", file_path="b.py", line=20)
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        assert f1.fingerprint != f2.fingerprint

    def test_to_dict(self):
        f = Finding(scanner="test", severity=Severity.HIGH, title="vuln")
        f.compute_fingerprint()
        d = f.to_dict()
        assert d["scanner"] == "test"
        assert d["severity"] == "HIGH"
        assert d["fingerprint"]


class TestSeverity:
    def test_from_str_valid(self):
        assert Severity.from_str("CRITICAL") == Severity.CRITICAL
        assert Severity.from_str("high") == Severity.HIGH

    def test_from_str_unknown(self):
        assert Severity.from_str("UNKNOWN") == Severity.LOW

    def test_ordering(self):
        assert Severity.CRITICAL < Severity.HIGH
        assert Severity.HIGH < Severity.MEDIUM
