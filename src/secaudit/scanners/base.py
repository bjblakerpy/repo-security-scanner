"""Abstract base class for all security scanners."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from secaudit.models import ScanResult


class BaseScanner(ABC):
    """All scanners implement this interface.

    To add a new scanner:
    1. Create a file in secaudit/scanners/
    2. Subclass BaseScanner and implement the 3 abstract methods
    3. Add one line to the registry in scanners/__init__.py
    """

    name: str = ""
    description: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner's external tool is installed and runnable."""
        ...

    @abstractmethod
    def is_applicable(self, repo_path: Path) -> bool:
        """Check if this scanner is relevant for the given repo.

        E.g., pip-audit only applies if requirements.txt exists.
        """
        ...

    @abstractmethod
    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        """Execute the scan and return structured results.

        Must NOT raise exceptions — capture errors in ScanResult.error.
        """
        ...

    def _check_tool(self, binary: str) -> bool:
        """Helper: check if a binary is on PATH."""
        return shutil.which(binary) is not None
