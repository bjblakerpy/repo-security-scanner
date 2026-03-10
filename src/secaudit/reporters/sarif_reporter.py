"""SARIF reporter — generates SARIF 2.1.0 JSON for GitHub Security tab."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from secaudit.config import AppConfig
from secaudit.models import Severity, TriageResult
from secaudit.reporters.base import BaseReporter

log = logging.getLogger(__name__)

# Map our severity to SARIF level
SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SarifReporter(BaseReporter):
    """Generates SARIF 2.1.0 JSON for GitHub Security tab integration.

    Groups findings by scanner into separate SARIF 'runs', each with its own
    tool driver and rule definitions. The output can be uploaded to GitHub via
    the codeql-action/upload-sarif action or the code scanning API.

    Kwargs:
        output_path (str): File path to write. Default "results.sarif".
    """

    name = "sarif"

    def report(self, triage: TriageResult, config: AppConfig, **kwargs) -> dict:
        output_path = kwargs.get("output_path", config.output_path or "results.sarif")

        sarif = self._build_sarif(triage)
        content = json.dumps(sarif, indent=2)

        if output_path:
            Path(output_path).write_text(content)
            log.info("SARIF results written to %s", output_path)

        return {"content": content, "path": output_path}

    def _build_sarif(self, triage: TriageResult) -> dict:
        """Build a SARIF 2.1.0 document from triage results."""
        # Group findings by scanner for tool runs
        by_scanner: dict[str, list] = {}
        for findings in triage.findings.values():
            for f in findings:
                by_scanner.setdefault(f.scanner, []).append(f)

        runs = []
        for scanner_name, findings in by_scanner.items():
            rules = {}
            results = []

            for f in findings:
                rule_id = f.fingerprint or f.title[:40]
                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": f.title[:80],
                        "shortDescription": {"text": f.title[:200]},
                        "defaultConfiguration": {"level": SARIF_LEVEL_MAP.get(f.severity, "warning")},
                        "helpUri": "",
                    }

                result = {
                    "ruleId": rule_id,
                    "level": SARIF_LEVEL_MAP.get(f.severity, "warning"),
                    "message": {"text": f"{f.description}\n\nRecommendation: {f.recommendation}"},
                }

                if f.file_path:
                    location = {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                        }
                    }
                    if f.line:
                        location["physicalLocation"]["region"] = {"startLine": f.line}
                    result["locations"] = [location]

                results.append(result)

            runs.append({
                "tool": {
                    "driver": {
                        "name": scanner_name,
                        "informationUri": "https://github.com/your-org/secaudit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            })

        # If no runs, create an empty one so SARIF is still valid
        if not runs:
            runs.append({
                "tool": {
                    "driver": {
                        "name": "secaudit",
                        "informationUri": "https://github.com/your-org/secaudit",
                        "rules": [],
                    }
                },
                "results": [],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
