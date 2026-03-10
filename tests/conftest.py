"""Shared test fixtures."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from secaudit.config import AppConfig, load_config
from secaudit.models import Finding, Severity, TriageResult


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a temporary directory that looks like a git repo."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    return tmp_path


@pytest.fixture
def python_repo(tmp_repo):
    """Temp repo with Python project files."""
    (tmp_repo / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
    (tmp_repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    return tmp_repo


@pytest.fixture
def node_repo(tmp_repo):
    """Temp repo with Node.js project files."""
    (tmp_repo / "package.json").write_text('{"name": "test", "dependencies": {"express": "^4.18.0"}}')
    (tmp_repo / "index.js").write_text("const express = require('express');\n")
    return tmp_repo


@pytest.fixture
def docker_repo(tmp_repo):
    """Temp repo with Dockerfile."""
    (tmp_repo / "Dockerfile").write_text("FROM node:18\nRUN npm install\nCOPY . .\n")
    return tmp_repo


@pytest.fixture
def sample_findings():
    """A set of sample findings for testing."""
    findings = [
        Finding(
            scanner="gitleaks",
            severity=Severity.CRITICAL,
            title="AWS Access Key detected",
            description="Found AWS access key in config.py",
            file_path="config.py",
            line=42,
            recommendation="Rotate this credential immediately",
        ),
        Finding(
            scanner="semgrep",
            severity=Severity.HIGH,
            title="SQL Injection in user_query",
            description="User input directly concatenated into SQL query",
            file_path="db.py",
            line=15,
            recommendation="Use parameterized queries",
        ),
        Finding(
            scanner="pip-audit",
            severity=Severity.HIGH,
            title="flask 2.0.0: CVE-2023-12345",
            description="Remote code execution vulnerability",
            recommendation="Upgrade to flask>=3.0.0",
        ),
        Finding(
            scanner="npm-audit",
            severity=Severity.MEDIUM,
            title="lodash: prototype pollution",
            description="Prototype pollution in lodash",
            recommendation="Run `npm audit fix`",
        ),
    ]
    for f in findings:
        f.compute_fingerprint()
    return findings


@pytest.fixture
def sample_triage(sample_findings):
    """A sample triage result."""
    return TriageResult(
        summary="2 critical/high findings require immediate attention.",
        findings={
            "CRITICAL": [sample_findings[0]],
            "HIGH": [sample_findings[1], sample_findings[2]],
            "MEDIUM": [sample_findings[3]],
            "LOW": [],
        },
        raw_count=4,
        triaged_count=4,
    )


@pytest.fixture
def default_config():
    """A minimal config with defaults."""
    return load_config()


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite database path."""
    return str(tmp_path / "test_findings.db")
