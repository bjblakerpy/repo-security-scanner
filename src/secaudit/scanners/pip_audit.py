"""pip-audit scanner — Python dependency vulnerability detection."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)


class PipAuditScanner(BaseScanner):
    """Scans Python dependencies for known CVEs using pip-audit.

    Checks installed packages against the PyPI advisory database.
    Applicable when requirements.txt, pyproject.toml, Pipfile,
    setup.py, or setup.cfg is present. All findings default to HIGH severity.
    """

    name = "pip-audit"
    description = "Python dependency vulnerability detection (CVEs)"

    def is_available(self) -> bool:
        """Check if pip-audit is installed."""
        return self._check_tool("pip-audit")

    def is_applicable(self, repo_path: Path) -> bool:
        """Applicable when Python dependency files exist."""
        return any(
            (repo_path / f).exists()
            for f in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg")
        )

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running pip-audit...")
        start = time.time()

        rc, stdout, stderr = run_command(
            ["pip-audit", "--format", "json"],
            cwd=repo_path,
            timeout=300,
        )

        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    fix_versions = vuln.get("fix_versions", [])
                    fix_str = f"Upgrade to {', '.join(fix_versions)}" if fix_versions else "No fix available yet"
                    f = Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"{dep['name']} {dep['version']}: {vuln['id']}",
                        description=vuln.get("description", ""),
                        recommendation=fix_str,
                        raw={
                            "package": dep["name"],
                            "installed_version": dep["version"],
                            "vuln_id": vuln["id"],
                            "fix_versions": fix_versions,
                        },
                    )
                    f.compute_fingerprint()
                    findings.append(f)
        except (json.JSONDecodeError, KeyError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
