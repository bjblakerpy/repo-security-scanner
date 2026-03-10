"""npm audit scanner — Node.js dependency vulnerability detection."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)


class NpmAuditScanner(BaseScanner):
    """Scans Node.js dependencies for known vulnerabilities using npm audit.

    Checks packages against the npm advisory database. Applicable when
    package.json is present. Severity is taken directly from npm's
    advisory severity field.
    """

    name = "npm-audit"
    description = "Node.js dependency vulnerability detection (CVEs)"

    def is_available(self) -> bool:
        """Check if npm is installed."""
        return self._check_tool("npm")

    def is_applicable(self, repo_path: Path) -> bool:
        """Applicable when package.json exists."""
        return (repo_path / "package.json").exists()

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running npm audit...")
        start = time.time()

        rc, stdout, stderr = run_command(
            ["npm", "audit", "--json"],
            cwd=repo_path,
            timeout=300,
        )

        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
            for name, info in data.get("vulnerabilities", {}).items():
                severity_str = info.get("severity", "unknown").upper()
                fix_available = info.get("fixAvailable", False)
                f = Finding(
                    scanner=self.name,
                    severity=Severity.from_str(severity_str),
                    title=f"{name}: {info.get('title', 'vulnerability')}",
                    description=info.get("title", ""),
                    recommendation="Run `npm audit fix`" if fix_available else "Manual review required",
                    raw={
                        "package": name,
                        "via": [str(v) for v in info.get("via", [])],
                        "fix_available": fix_available,
                    },
                )
                f.compute_fingerprint()
                findings.append(f)
        except (json.JSONDecodeError, KeyError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
