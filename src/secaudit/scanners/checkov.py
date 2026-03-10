"""Checkov scanner — Infrastructure as Code misconfiguration detection."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.utils.subprocess_runner import run_command

log = logging.getLogger(__name__)

# File patterns that indicate IaC is present
IAC_PATTERNS = [
    "*.tf",
    "*.tfvars",
    "cloudformation*.yml",
    "cloudformation*.yaml",
    "cloudformation*.json",
    "*.template",
    "k8s/*.yml",
    "k8s/*.yaml",
    "kubernetes/*.yml",
    "kubernetes/*.yaml",
    "helm/**/templates/*.yaml",
]


class CheckovScanner(BaseScanner):
    """Detects misconfigurations in Infrastructure as Code (IaC) files.

    Scans Terraform, CloudFormation, Kubernetes YAML, and Helm charts
    for security misconfigurations such as overly permissive IAM policies,
    unencrypted storage, and missing network restrictions.

    Config options:
        frameworks (list[str]): IaC frameworks to check (e.g., ["terraform", "cloudformation"]).
            Empty list auto-detects.
        timeout (int): Max seconds for the scan. Default 600.
    """

    name = "checkov"
    description = "Infrastructure as Code misconfiguration detection"

    def is_available(self) -> bool:
        return self._check_tool("checkov")

    def is_applicable(self, repo_path: Path) -> bool:
        for pattern in IAC_PATTERNS:
            if list(repo_path.glob(pattern)):
                return True
        return False

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        log.info("Running checkov...")
        start = time.time()
        config = config or {}

        cmd = [
            "checkov",
            "-d", str(repo_path),
            "--output", "json",
            "--quiet",
            "--compact",
        ]

        frameworks = config.get("frameworks")
        if frameworks:
            cmd.extend(["--framework", ",".join(frameworks)])

        rc, stdout, stderr = run_command(cmd, cwd=repo_path, timeout=config.get("timeout", 600))

        findings: list[Finding] = []
        try:
            # Checkov may output a list or a single object
            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]

            for check_type in data:
                for result in check_type.get("results", {}).get("failed_checks", []):
                    severity_str = result.get("severity", "MEDIUM")
                    if isinstance(severity_str, str):
                        severity_str = severity_str.upper()
                    else:
                        severity_str = "MEDIUM"

                    f = Finding(
                        scanner=self.name,
                        severity=Severity.from_str(severity_str),
                        title=f"{result.get('check_id', '')}: {result.get('check_name', 'unknown')}",
                        description=result.get("check_name", ""),
                        file_path=result.get("file_path"),
                        line=result.get("file_line_range", [None])[0],
                        recommendation=result.get("guideline", "Review IaC configuration"),
                        raw=result,
                    )
                    f.compute_fingerprint()
                    findings.append(f)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return ScanResult(self.name, str(repo_path), [], time.time() - start, error=str(e))

        return ScanResult(self.name, str(repo_path), findings, time.time() - start)
