"""Tests for email and Notion reporters."""

import json
from unittest.mock import MagicMock, patch

import pytest

from secaudit.config import AppConfig, EmailConfig, NotionConfig
from secaudit.models import Finding, Severity, TriageResult
from secaudit.reporters.email import EmailReporter, _build_html
from secaudit.reporters.notion import NotionReporter, _create_page, _check_existing


@pytest.fixture
def app_config():
    config = AppConfig()
    config.email = EmailConfig(
        enabled=True,
        smtp_host="smtp.test.com",
        smtp_port=587,
        username="user@test.com",
        password="pass123",
        from_addr="user@test.com",
        to=["recipient@test.com"],
        send_on="all",
    )
    config.notion = NotionConfig(
        enabled=True,
        token="secret_test_token",
        database_id="db-id-123",
        deduplicate=True,
    )
    return config


class TestEmailReporter:
    def test_build_html_with_findings(self, sample_triage):
        html = _build_html(sample_triage, repo_name="test/repo")
        assert "Security Scan Digest" in html
        assert "test/repo" in html
        assert "CRITICAL" in html
        assert "AWS Access Key" in html

    def test_build_html_no_findings(self):
        empty = TriageResult(summary="Clean", findings={}, raw_count=0, triaged_count=0)
        html = _build_html(empty)
        assert "No findings to report" in html

    def test_build_html_includes_notion_links(self, sample_triage):
        notion_urls = {"CRITICAL": ["https://notion.so/page1"]}
        html = _build_html(sample_triage, notion_urls=notion_urls)
        assert "notion.so/page1" in html
        assert "View in Notion" in html

    def test_skip_when_not_configured(self, sample_triage):
        config = AppConfig()
        config.email = EmailConfig(enabled=False)
        reporter = EmailReporter()
        result = reporter.report(sample_triage, config)
        assert result == {}

    def test_skip_when_no_credentials(self, sample_triage):
        config = AppConfig()
        config.email = EmailConfig(enabled=True, username="", password="", to=[])
        reporter = EmailReporter()
        result = reporter.report(sample_triage, config)
        assert result == {}

    def test_send_on_findings_only_skips_empty(self, app_config):
        app_config.email.send_on = "findings_only"
        empty = TriageResult(summary="Clean", findings={}, raw_count=0, triaged_count=0)
        reporter = EmailReporter()
        result = reporter.report(empty, app_config)
        assert result == {}

    def test_send_on_critical_only_skips_non_critical(self, app_config):
        app_config.email.send_on = "critical_only"
        medium_only = TriageResult(
            summary="Medium only",
            findings={"MEDIUM": [Finding(scanner="test", severity=Severity.MEDIUM, title="minor")]},
            raw_count=1, triaged_count=1,
        )
        reporter = EmailReporter()
        result = reporter.report(medium_only, app_config)
        assert result == {}

    def test_sends_email_successfully(self, sample_triage, app_config):
        reporter = EmailReporter()
        with patch("secaudit.reporters.email.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = reporter.report(sample_triage, app_config)

        assert "sent_to" in result
        assert result["sent_to"] == ["recipient@test.com"]
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@test.com", "pass123")

    def test_subject_line_with_critical(self, sample_triage, app_config):
        reporter = EmailReporter()
        with patch("secaudit.reporters.email.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

            result = reporter.report(sample_triage, app_config)

        assert "1 Critical" in result["subject"]

    def test_handles_smtp_error(self, sample_triage, app_config):
        reporter = EmailReporter()
        with patch("secaudit.reporters.email.smtplib.SMTP", side_effect=ConnectionError("refused")):
            result = reporter.report(sample_triage, app_config)

        assert "error" in result


class TestNotionReporter:
    def test_skip_when_not_configured(self, sample_triage):
        config = AppConfig()
        config.notion = NotionConfig(enabled=False)
        reporter = NotionReporter()
        result = reporter.report(sample_triage, config)
        assert result == {"urls": {}}

    def test_creates_pages(self, sample_triage, app_config):
        reporter = NotionReporter()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"url": "https://notion.so/page123"}

        with patch("secaudit.reporters.notion.requests.post", return_value=mock_resp), \
             patch("secaudit.reporters.notion._check_existing", return_value=False), \
             patch("secaudit.reporters.notion._limiter"):
            result = reporter.report(sample_triage, app_config)

        urls = result["urls"]
        total_urls = sum(len(v) for v in urls.values())
        assert total_urls > 0

    def test_dedup_skips_existing(self, sample_triage, app_config):
        reporter = NotionReporter()

        with patch("secaudit.reporters.notion._create_page", return_value="https://notion.so/page") as mock_create, \
             patch("secaudit.reporters.notion._check_existing", return_value=True):
            result = reporter.report(sample_triage, app_config)

        # Should not create any pages since all are "existing"
        mock_create.assert_not_called()

    def test_dedup_disabled(self, sample_triage, app_config):
        app_config.notion.deduplicate = False
        reporter = NotionReporter()

        with patch("secaudit.reporters.notion._create_page", return_value="https://notion.so/page") as mock_create, \
             patch("secaudit.reporters.notion._check_existing") as mock_check:
            result = reporter.report(sample_triage, app_config)

        # Should not even check for existing when dedup is disabled
        mock_check.assert_not_called()
