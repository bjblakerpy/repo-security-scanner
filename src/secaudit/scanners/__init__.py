"""Scanner registry — maps scanner names to their classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secaudit.scanners.base import BaseScanner


def _build_registry() -> dict[str, type[BaseScanner]]:
    """Lazy import to avoid circular deps and missing optional deps."""
    from secaudit.scanners.checkov import CheckovScanner
    from secaudit.scanners.gitleaks import GitleaksScanner
    from secaudit.scanners.hadolint import HadolintScanner
    from secaudit.scanners.licenses import LicenseScanner
    from secaudit.scanners.npm_audit import NpmAuditScanner
    from secaudit.scanners.pip_audit import PipAuditScanner
    from secaudit.scanners.semgrep import SemgrepScanner
    from secaudit.scanners.trivy import TrivyScanner

    return {
        "gitleaks": GitleaksScanner,
        "semgrep": SemgrepScanner,
        "pip-audit": PipAuditScanner,
        "npm-audit": NpmAuditScanner,
        "trivy": TrivyScanner,
        "checkov": CheckovScanner,
        "hadolint": HadolintScanner,
        "licenses": LicenseScanner,
    }


def get_scanner(name: str) -> BaseScanner:
    """Get a scanner instance by name."""
    registry = _build_registry()
    cls = registry.get(name)
    if cls is None:
        raise ValueError(f"Unknown scanner: {name}. Available: {list(registry.keys())}")
    return cls()


def get_all_scanners() -> list[BaseScanner]:
    """Get instances of all registered scanners."""
    return [cls() for cls in _build_registry().values()]


def list_scanner_names() -> list[str]:
    """Return all registered scanner names."""
    return list(_build_registry().keys())
