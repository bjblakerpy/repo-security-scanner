"""Trivy scanner — container image and filesystem vulnerability scanning."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)


class TrivyScanner(BaseScanner):
    """Scans container images and filesystems for OS and language package CVEs.

    Uses the trivy binary in filesystem mode to detect vulnerabilities
    in Dockerfiles, container images, and installed packages. Applicable
    when Dockerfile, docker-compose.yml, or Containerfile is present.

    Config options:
        severity (str): Comma-separated severity filter. Default "CRITICAL,HIGH,MEDIUM".
        timeout (int): Max seconds for the scan. Default 600.
    """

    name = "trivy"
    description = "Container image and filesystem vulnerability scanning"

    def is_available(self) -> bool:
        """Check if the trivy binary is installed."""
        return self._check_tool("trivy")

    def is_applicable(self, repo_path: Path) -> bool:
        """Applicable when Dockerfile, docker-compose.yml, or Containerfile exists."""
        indicators = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Containerfile"]
        for name in indicators:
            if (repo_path / name).exists():
                return True
        # Also check for Dockerfile.* variants
        return any(repo_path.glob("Dockerfile*"))

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running trivy filesystem scan...")
        start = time.time()
        config = config or {}

        severity_filter = config.get("severity", "CRITICAL,HIGH,MEDIUM")
        cmd = [
            "trivy", "filesystem",
            "--format", "json",
            "--severity", severity_filter,
            "--quiet",
            str(repo_path),
        ]

        rc, stdout, stderr = run_command(cmd, cwd=repo_path, timeout=config.get("timeout", 600))

        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
            for result in data.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    severity_str = vuln.get("Severity", "UNKNOWN").upper()
                    fix_version = vuln.get("FixedVersion", "")
                    f = Finding(
                        scanner=self.name,
                        severity=Severity.from_str(severity_str),
                        title=f"{vuln.get('PkgName', 'unknown')}: {vuln.get('VulnerabilityID', '')}",
                        description=vuln.get("Title", ""),
                        file_path=target,
                        recommendation=f"Upgrade to {fix_version}" if fix_version else "No fix available yet",
                        raw={
                            "vuln_id": vuln.get("VulnerabilityID"),
                            "package": vuln.get("PkgName"),
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": fix_version,
                            "data_source": vuln.get("DataSource", {}).get("Name", ""),
                        },
                    )
                    f.compute_fingerprint()
                    findings.append(f)
        except (json.JSONDecodeError, KeyError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
