"""Tests for reporters."""

import json
from pathlib import Path

import pytest

from secaudit.config import load_config
from secaudit.reporters.json_export import JsonExportReporter
from secaudit.reporters.sarif_reporter import SarifReporter


class TestJsonExport:
    def test_json_output(self, sample_triage, default_config):
        reporter = JsonExportReporter()
        result = reporter.report(sample_triage, default_config)
        data = json.loads(result["content"])
        assert "summary" in data
        assert "critical" in data
        assert len(data["critical"]) == 1
        assert len(data["high"]) == 2

    def test_json_to_file(self, sample_triage, default_config, tmp_path):
        output = str(tmp_path / "results.json")
        reporter = JsonExportReporter()
        reporter.report(sample_triage, default_config, output_path=output)
        assert Path(output).exists()
        data = json.loads(Path(output).read_text())
        assert data["summary"] == sample_triage.summary

    def test_csv_output(self, sample_triage, default_config):
        reporter = JsonExportReporter()
        result = reporter.report(sample_triage, default_config, format="csv")
        lines = result["content"].strip().split("\n")
        assert len(lines) == 5  # header + 4 findings


class TestSarifReporter:
    def test_sarif_structure(self, sample_triage, default_config):
        reporter = SarifReporter()
        result = reporter.report(sample_triage, default_config, output_path=None)
        data = json.loads(result["content"])
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) > 0
        # Should have results
        total_results = sum(len(run["results"]) for run in data["runs"])
        assert total_results == 4

    def test_sarif_to_file(self, sample_triage, default_config, tmp_path):
        output = str(tmp_path / "results.sarif")
        reporter = SarifReporter()
        reporter.report(sample_triage, default_config, output_path=output)
        assert Path(output).exists()

    def test_empty_triage_produces_valid_sarif(self, default_config):
        from secaudit.models import TriageResult
        empty = TriageResult(summary="No findings", findings={}, raw_count=0, triaged_count=0)
        reporter = SarifReporter()
        result = reporter.report(empty, default_config, output_path=None)
        data = json.loads(result["content"])
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 0
