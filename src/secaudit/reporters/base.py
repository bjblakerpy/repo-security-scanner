"""Abstract base class for all reporters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from secaudit.config import AppConfig
from secaudit.models import TriageResult


class BaseReporter(ABC):
    """All reporters implement this interface."""

    name: str = ""

    @abstractmethod
    def report(self, triage: TriageResult, config: AppConfig, **kwargs) -> dict:
        """Generate and deliver a report.

        Args:
            triage: The triage result to report.
            config: Application config.
            **kwargs: Reporter-specific arguments (e.g., notion_urls, repo_name).

        Returns:
            Dict with reporter-specific metadata (e.g., URLs created, files written).
        """
        ...
