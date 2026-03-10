"""Gitleaks scanner — detects secrets and credentials in git history."""

from __future__ import annotations

import json
import logging
import tempfile
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    """Detects hardcoded secrets and credentials across full git history.

    Uses the gitleaks binary to scan all commits for API keys, passwords,
    tokens, and other sensitive data. All findings are marked CRITICAL since
    leaked secrets require immediate rotation.

    Config options:
        full_history (bool): Scan all commits, not just HEAD. Default True.
        config_path (str): Path to a custom .gitleaks.toml rules file.
        timeout (int): Max seconds for the scan. Default 300.
    """

    name = "gitleaks"
    description = "Secret detection in git history"

    def is_available(self) -> bool:
        """Check if the gitleaks binary is installed."""
        return self._check_tool("gitleaks")

    def is_applicable(self, repo_path: Path) -> bool:
        """Applicable to any directory with a .git folder."""
        return (repo_path / ".git").is_dir()

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running gitleaks...")
        start = time.time()
        config = config or {}

        report_path = Path(tempfile.mktemp(suffix=".json"))
        cmd = [
            "gitleaks", "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
        ]
        if config.get("full_history", True):
            cmd.extend(["--log-opts=--all"])

        custom_config = config.get("config_path")
        if custom_config:
            cmd.extend(["--config", custom_config])

        rc, stdout, stderr = run_command(cmd, cwd=repo_path, timeout=config.get("timeout", 300))

        findings: list[Finding] = []
        try:
            if report_path.exists():
                raw_findings = json.loads(report_path.read_text())
                for item in raw_findings or []:
                    f = Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Secret detected: {item.get('RuleID', 'unknown')}",
                        description=item.get("Description", ""),
                        file_path=item.get("File"),
                        line=item.get("StartLine"),
                        recommendation=f"Rotate this credential and remove from git history",
                        raw=item,
                    )
                    f.compute_fingerprint()
                    findings.append(f)
        except (json.JSONDecodeError, OSError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))
        finally:
            report_path.unlink(missing_ok=True)

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
