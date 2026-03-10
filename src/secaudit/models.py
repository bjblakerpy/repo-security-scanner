"""Core data models used across the entire scanning pipeline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a severity string, defaulting to LOW for unknowns."""
        try:
            return cls(value.upper())
        except ValueError:
            return cls.LOW

    def __lt__(self, other: Severity) -> bool:
        order = list(Severity)
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A single security finding from any scanner."""

    scanner: str
    severity: Severity
    title: str
    description: str = ""
    file_path: str | None = None
    line: int | None = None
    recommendation: str = ""
    fingerprint: str = ""
    raw: dict = field(default_factory=dict)

    def compute_fingerprint(self) -> str:
        """Generate a stable fingerprint for deduplication across runs."""
        key_parts = [
            self.scanner,
            self.title,
            self.file_path or "",
            str(self.line or ""),
        ]
        # Include rule_id or vuln_id from raw data if available
        for k in ("RuleID", "check_id", "vuln_id", "id"):
            if k in self.raw:
                key_parts.append(str(self.raw[k]))
                break
        self.fingerprint = hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "recommendation": self.recommendation,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    """Result from a single scanner run against one repo."""

    scanner_name: str
    repo: str
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class TriageResult:
    """Output from Claude triage — findings grouped by severity."""

    summary: str
    findings: dict[str, list[Finding]] = field(default_factory=dict)
    raw_count: int = 0
    triaged_count: int = 0

    @property
    def has_critical(self) -> bool:
        return len(self.findings.get("CRITICAL", [])) > 0

    @property
    def total_findings(self) -> int:
        return sum(len(v) for v in self.findings.values())

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "raw_count": self.raw_count,
            "triaged_count": self.triaged_count,
            "critical": [f.to_dict() for f in self.findings.get("CRITICAL", [])],
            "high": [f.to_dict() for f in self.findings.get("HIGH", [])],
            "medium": [f.to_dict() for f in self.findings.get("MEDIUM", [])],
            "low": [f.to_dict() for f in self.findings.get("LOW", [])],
        }


@dataclass
class RepoTarget:
    """A repository to scan — either a local path or a GitHub URL."""

    name: str = ""
    url: str | None = None
    path: Path | None = None
    ref: str | None = None  # branch/tag/commit
    owner: str = ""
    repo_name: str = ""

    @classmethod
    def from_path(cls, path: str | Path) -> RepoTarget:
        p = Path(path).resolve()
        return cls(name=p.name, path=p)

    @classmethod
    def from_url(cls, url: str, ref: str | None = None) -> RepoTarget:
        # Parse owner/repo from GitHub URL
        parts = url.rstrip("/").rstrip(".git").split("/")
        owner = parts[-2] if len(parts) >= 2 else ""
        repo_name = parts[-1] if parts else ""
        return cls(
            name=f"{owner}/{repo_name}" if owner else repo_name,
            url=url,
            ref=ref,
            owner=owner,
            repo_name=repo_name,
        )

    @classmethod
    def from_spec(cls, spec: str) -> RepoTarget:
        """Parse a repo spec — could be a local path, GitHub URL, or owner/repo shorthand."""
        if spec.startswith(("http://", "https://", "git@")):
            return cls.from_url(spec)
        p = Path(spec)
        if p.exists():
            return cls.from_path(spec)
        # Assume owner/repo shorthand
        if "/" in spec and not spec.startswith("/"):
            return cls.from_url(f"https://github.com/{spec}")
        return cls.from_path(spec)
