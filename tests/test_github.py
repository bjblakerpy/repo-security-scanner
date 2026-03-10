"""Tests for GitHub client and PR commenter."""

import json
from unittest.mock import MagicMock, patch

import pytest

from secaudit.config import AppConfig, GithubConfig, GithubReportingConfig
from secaudit.github.client import GitHubClient
from secaudit.github.pr_commenter import PRCommenter, _build_comment
from secaudit.models import Finding, Severity, TriageResult


@pytest.fixture
def gh_config():
    return GithubConfig(token="ghp_test_token", org="test-org")


@pytest.fixture
def gh_client(gh_config):
    return GitHubClient(gh_config)


def _mock_response(status_code=200, json_data=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.text = json.dumps(json_data or {})
    mock.raise_for_status = MagicMock()
    return mock


class TestGitHubClient:
    def test_list_org_repos(self, gh_client):
        repos_data = [
            {"full_name": "test-org/repo-1", "name": "repo-1", "clone_url": "https://github.com/test-org/repo-1.git", "fork": False, "archived": False},
            {"full_name": "test-org/repo-2", "name": "repo-2", "clone_url": "https://github.com/test-org/repo-2.git", "fork": False, "archived": False},
        ]
        # First page returns repos, second page returns empty to stop pagination
        with patch.object(gh_client._session, "get", side_effect=[
            _mock_response(json_data=repos_data),
            _mock_response(json_data=[]),
        ]):
            targets = gh_client.list_org_repos()

        assert len(targets) == 2
        assert targets[0].name == "test-org/repo-1"
        assert targets[1].name == "test-org/repo-2"

    def test_list_org_repos_excludes_forks(self, gh_client):
        repos_data = [
            {"full_name": "test-org/original", "name": "original", "clone_url": "https://...", "fork": False, "archived": False},
            {"full_name": "test-org/forked", "name": "forked", "clone_url": "https://...", "fork": True, "archived": False},
        ]
        with patch.object(gh_client._session, "get", side_effect=[
            _mock_response(json_data=repos_data),
            _mock_response(json_data=[]),
        ]):
            targets = gh_client.list_org_repos()

        assert len(targets) == 1
        assert targets[0].repo_name == "original"

    def test_list_org_repos_excludes_archived(self, gh_client):
        repos_data = [
            {"full_name": "test-org/active", "name": "active", "clone_url": "https://...", "fork": False, "archived": False},
            {"full_name": "test-org/old", "name": "old", "clone_url": "https://...", "fork": False, "archived": True},
        ]
        with patch.object(gh_client._session, "get", side_effect=[
            _mock_response(json_data=repos_data),
            _mock_response(json_data=[]),
        ]):
            targets = gh_client.list_org_repos()

        assert len(targets) == 1

    def test_list_org_repos_excludes_configured(self, gh_config):
        gh_config.exclude_repos = ["test-org/skip-me"]
        client = GitHubClient(gh_config)
        repos_data = [
            {"full_name": "test-org/keep", "name": "keep", "clone_url": "https://...", "fork": False, "archived": False},
            {"full_name": "test-org/skip-me", "name": "skip-me", "clone_url": "https://...", "fork": False, "archived": False},
        ]
        with patch.object(client._session, "get", side_effect=[
            _mock_response(json_data=repos_data),
            _mock_response(json_data=[]),
        ]):
            targets = client.list_org_repos()

        assert len(targets) == 1
        assert targets[0].repo_name == "keep"

    def test_empty_org_returns_empty(self):
        config = GithubConfig(token="ghp_test", org="")
        client = GitHubClient(config)
        assert client.list_org_repos() == []

    def test_create_issue(self, gh_client):
        issue_data = {"html_url": "https://github.com/test-org/repo/issues/1", "number": 1}
        with patch.object(gh_client._session, "post", return_value=_mock_response(json_data=issue_data)):
            result = gh_client.create_issue("test-org", "repo", "Title", "Body", labels=["security"])

        assert result["html_url"] == "https://github.com/test-org/repo/issues/1"

    def test_find_existing_issue_found(self, gh_client):
        issues = [{"title": "[abc123] Security finding", "html_url": "https://..."}]
        with patch.object(gh_client._session, "get", return_value=_mock_response(json_data=issues)):
            result = gh_client.find_existing_issue("test-org", "repo", "abc123")

        assert result is not None

    def test_find_existing_issue_not_found(self, gh_client):
        with patch.object(gh_client._session, "get", return_value=_mock_response(json_data=[])):
            result = gh_client.find_existing_issue("test-org", "repo", "xyz789")

        assert result is None

    def test_get_changed_files(self, gh_client):
        files = [{"filename": "app.py"}, {"filename": "utils.py"}]
        with patch.object(gh_client._session, "get", return_value=_mock_response(json_data=files)):
            result = gh_client.get_changed_files("owner", "repo", 42)

        assert result == ["app.py", "utils.py"]


class TestPRComment:
    @pytest.fixture
    def triage(self, sample_findings):
        return TriageResult(
            summary="2 critical/high findings.",
            findings={
                "CRITICAL": [sample_findings[0]],
                "HIGH": [sample_findings[1]],
                "MEDIUM": [],
                "LOW": [],
            },
            raw_count=2,
            triaged_count=2,
        )

    def test_build_comment_with_findings(self, triage):
        comment = _build_comment(triage)
        assert "Security Scan Results" in comment
        assert "CRITICAL" in comment
        assert "AWS Access Key" in comment
        assert "<details>" in comment
        assert "secaudit" in comment

    def test_build_comment_no_findings(self):
        empty = TriageResult(summary="Clean", findings={}, raw_count=0, triaged_count=0)
        comment = _build_comment(empty)
        assert "No security findings" in comment

    def test_build_comment_contains_marker(self, triage):
        comment = _build_comment(triage)
        assert "<!-- secaudit-scan-results -->" in comment

    def test_post_or_update_creates_new(self, triage):
        app_config = AppConfig()
        app_config.github.token = "ghp_test"
        commenter = PRCommenter(app_config)

        # No existing comment found, create new
        with patch.object(commenter, "_find_existing_comment", return_value=None), \
             patch.object(commenter, "_create_comment", return_value="https://github.com/comment/1") as mock_create:
            url = commenter.post_or_update("owner", "repo", 42, triage)

        assert url == "https://github.com/comment/1"
        mock_create.assert_called_once()

    def test_post_or_update_updates_existing(self, triage):
        app_config = AppConfig()
        app_config.github.token = "ghp_test"
        commenter = PRCommenter(app_config)

        with patch.object(commenter, "_find_existing_comment", return_value=123), \
             patch.object(commenter, "_update_comment", return_value="https://github.com/comment/123") as mock_update:
            url = commenter.post_or_update("owner", "repo", 42, triage)

        assert url == "https://github.com/comment/123"
        mock_update.assert_called_once()
