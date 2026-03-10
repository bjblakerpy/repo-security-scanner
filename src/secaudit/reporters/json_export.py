"""JSON and CSV export reporter."""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path

from secaudit.config import AppConfig
from secaudit.models import TriageResult
from secaudit.reporters.base import BaseReporter

log = logging.getLogger(__name__)


class JsonExportReporter(BaseReporter):
    """Exports triage results to JSON or CSV files.

    JSON output mirrors the TriageResult.to_dict() structure.
    CSV output flattens all findings into rows with columns:
    severity, title, description, scanner, recommendation, file_path, fingerprint.

    Kwargs:
        output_path (str): File path to write. Falls back to config.output_path.
        format (str): "json" (default) or "csv".
    """

    name = "json-export"

    def report(self, triage: TriageResult, config: AppConfig, **kwargs) -> dict:
        output_path = kwargs.get("output_path", config.output_path)
        fmt = kwargs.get("format", "json")

        data = triage.to_dict()

        if fmt == "csv":
            return self._write_csv(data, output_path)

        content = json.dumps(data, indent=2)
        if output_path:
            Path(output_path).write_text(content)
            log.info("JSON results written to %s", output_path)
        return {"content": content, "path": output_path}

    def _write_csv(self, data: dict, output_path: str | None) -> dict:
        """Flatten findings into CSV rows."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["severity", "title", "description", "scanner", "recommendation", "file_path", "fingerprint"])

        for severity in ("critical", "high", "medium", "low"):
            for finding in data.get(severity, []):
                writer.writerow([
                    severity.upper(),
                    finding.get("title", ""),
                    finding.get("description", ""),
                    finding.get("scanner", ""),
                    finding.get("recommendation", ""),
                    finding.get("file_path", ""),
                    finding.get("fingerprint", ""),
                ])

        content = output.getvalue()
        if output_path:
            Path(output_path).write_text(content)
            log.info("CSV results written to %s", output_path)
        return {"content": content, "path": output_path}
