"""Semgrep scanner — static analysis for injection, XSS, insecure patterns."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    """Static application security testing (SAST) using Semgrep.

    Runs Semgrep with configurable rulesets to detect injection, XSS,
    insecure cryptography, and other code-level vulnerabilities across
    20+ languages.

    Config options:
        config (str): Semgrep ruleset — "auto" (default), or path to custom rules.
        exclude (list[str]): Glob patterns to exclude (e.g., "tests/").
        timeout (int): Max seconds for the scan. Default 600.
    """

    name = "semgrep"
    description = "Static analysis (SAST) — injection, XSS, insecure patterns"

    def is_available(self) -> bool:
        """Check if the semgrep binary is installed."""
        return self._check_tool("semgrep")

    def is_applicable(self, repo_path: Path) -> bool:
        """Applicable to any repo with source code files."""
        # Semgrep can scan most languages — applicable to any repo with source code
        code_extensions = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".c", ".cpp", ".rs"}
        for p in repo_path.rglob("*"):
            if p.suffix in code_extensions and not any(part.startswith(".") for part in p.parts):
                return True
            # Stop early after checking a reasonable number of files
            if p.stat().st_size > 0:
                return True
        return True  # Default to applicable

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running semgrep...")
        start = time.time()
        config = config or {}

        semgrep_config = config.get("config", "auto")
        cmd = ["semgrep", f"--config={semgrep_config}", "--json", "--quiet"]

        exclude = config.get("exclude", [])
        for pattern in exclude:
            cmd.extend(["--exclude", pattern])

        cmd.append(str(repo_path))

        rc, stdout, stderr = run_command(cmd, cwd=repo_path, timeout=config.get("timeout", 600))

        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
            for result in data.get("results", []):
                severity_str = result.get("extra", {}).get("severity", "WARNING")
                f = Finding(
                    scanner=self.name,
                    severity=Severity.from_str(severity_str),
                    title=result.get("check_id", "unknown"),
                    description=result.get("extra", {}).get("message", ""),
                    file_path=result.get("path"),
                    line=result.get("start", {}).get("line"),
                    recommendation=result.get("extra", {}).get("fix", "Review and fix the flagged pattern"),
                    raw=result,
                )
                f.compute_fingerprint()
                findings.append(f)
        except (json.JSONDecodeError, KeyError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
