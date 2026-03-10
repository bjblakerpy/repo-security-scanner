"""Hadolint scanner — Dockerfile best practices linting."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)

# Map hadolint severity levels to our Severity enum
HADOLINT_SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


class HadolintScanner(BaseScanner):
    """Lints Dockerfiles for security and best practice violations.

    Uses hadolint to check for issues like running as root, using
    latest tags, missing health checks, and shell injection risks.
    Scans all Dockerfile* files in the repo root.
    """

    name = "hadolint"
    description = "Dockerfile best practices linting"

    def is_available(self) -> bool:
        """Check if the hadolint binary is installed."""
        return self._check_tool("hadolint")

    def is_applicable(self, repo_path: Path) -> bool:
        return bool(list(repo_path.glob("Dockerfile*")))

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running hadolint...")
        start = time.time()

        # Find all Dockerfiles
        dockerfiles = list(repo_path.glob("Dockerfile*"))
        findings: list[Finding] = []

        for dockerfile in dockerfiles:
            rc, stdout, stderr = run_command(
                ["hadolint", "--format", "json", str(dockerfile)],
                cwd=repo_path,
                timeout=60,
            )

            try:
                results = json.loads(stdout)
                for item in results:
                    severity = HADOLINT_SEVERITY_MAP.get(
                        item.get("level", "warning"),
                        Severity.MEDIUM,
                    )
                    f = Finding(
                        scanner=self.name,
                        severity=severity,
                        title=f"{item.get('code', 'unknown')}: {item.get('message', '')}",
                        description=item.get("message", ""),
                        file_path=str(dockerfile.relative_to(repo_path)),
                        line=item.get("line"),
                        recommendation=f"See https://github.com/hadolint/hadolint/wiki/{item.get('code', '')}",
                        raw=item,
                    )
                    f.compute_fingerprint()
                    findings.append(f)
            except (json.JSONDecodeError, KeyError):
                continue

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
