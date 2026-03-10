"""License compliance scanner — flags restricted/copyleft licenses in dependencies."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)

# Default denied licenses (copyleft / restrictive)
DEFAULT_DENIED_LICENSES = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "AGPL-1.0",
    "SSPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "CPAL-1.0",
    "OSL-3.0",
]


class LicenseScanner(BaseScanner):
    """Checks dependency licenses for copyleft or restricted terms.

    Uses pip-licenses (Python) and license-checker (Node) to enumerate
    dependency licenses, then flags any that match a configurable deny
    list. Defaults to flagging GPL, AGPL, SSPL, and other copyleft licenses.

    Config options:
        denied_licenses (list[str]): License identifiers to flag.
            Defaults to GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, and others.
    """

    name = "licenses"
    description = "License compliance — flags copyleft/restricted licenses"

    def is_available(self) -> bool:
        """Check if pip-licenses or license-checker is installed."""
        return self._check_tool("pip-licenses") or self._check_tool("license-checker")

    def is_applicable(self, repo_path: Path) -> bool:
        return (
            (repo_path / "requirements.txt").exists()
            or (repo_path / "pyproject.toml").exists()
            or (repo_path / "package.json").exists()
        )

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running license compliance check...")
        start = time.time()
        config = config or {}

        denied = config.get("denied_licenses", DEFAULT_DENIED_LICENSES)
        findings: list[Finding] = []

        # Python licenses
        if self._check_tool("pip-licenses") and any(
            (repo_path / f).exists()
            for f in ("requirements.txt", "pyproject.toml", "Pipfile")
        ):
            findings.extend(self._scan_python(repo_path, denied))

        # Node licenses
        if self._check_tool("license-checker") and (repo_path / "package.json").exists():
            findings.extend(self._scan_node(repo_path, denied))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)

    def _scan_python(self, repo_path: Path, denied: list[str]) -> list[Finding]:
        rc, stdout, stderr = run_command(
            ["pip-licenses", "--format=json", "--with-urls"],
            cwd=repo_path,
            timeout=120,
        )
        findings = []
        try:
            packages = json.loads(stdout)
            for pkg in packages:
                license_name = pkg.get("License", "UNKNOWN")
                # Check if any denied license matches
                for denied_lic in denied:
                    if denied_lic.lower() in license_name.lower():
                        f = Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            title=f"Restricted license: {pkg.get('Name', 'unknown')} ({license_name})",
                            description=f"Package {pkg.get('Name')} v{pkg.get('Version')} uses {license_name}",
                            recommendation=f"Replace with a permissively-licensed alternative or obtain a commercial license",
                            raw=pkg,
                        )
                        f.compute_fingerprint()
                        findings.append(f)
                        break
        except (json.JSONDecodeError, KeyError):
            pass
        return findings

    def _scan_node(self, repo_path: Path, denied: list[str]) -> list[Finding]:
        rc, stdout, stderr = run_command(
            ["license-checker", "--json", "--production"],
            cwd=repo_path,
            timeout=120,
        )
        findings = []
        try:
            packages = json.loads(stdout)
            for pkg_name, info in packages.items():
                license_name = info.get("licenses", "UNKNOWN")
                if isinstance(license_name, list):
                    license_name = ", ".join(license_name)
                for denied_lic in denied:
                    if denied_lic.lower() in license_name.lower():
                        f = Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            title=f"Restricted license: {pkg_name} ({license_name})",
                            description=f"Package {pkg_name} uses {license_name}",
                            recommendation="Replace with a permissively-licensed alternative or obtain a commercial license",
                            raw=info,
                        )
                        f.compute_fingerprint()
                        findings.append(f)
                        break
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
