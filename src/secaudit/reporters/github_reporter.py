"""GitHub reporter — PR comments and issue creation for critical findings."""

from __future__ import annotations

import logging

from secaudit.config import AppConfig
from secaudit.github.client import GitHubClient
from secaudit.github.pr_commenter import PRCommenter
from secaudit.models import Severity, TriageResult
from secaudit.reporters.base import BaseReporter

log = logging.getLogger(__name__)


class GitHubReporter(BaseReporter):
    name = "github"

    def report(self, triage: TriageResult, config: AppConfig, **kwargs) -> dict:
        if not config.github.token:
            log.warning("No GitHub token configured, skipping GitHub reporting")
            return {}

        owner = kwargs.get("owner", "")
        repo = kwargs.get("repo", "")
        pr_number = kwargs.get("pr_number")
        result: dict = {}

        if not owner or not repo:
            log.warning("No owner/repo specified for GitHub reporting")
            return {}

        # PR comments
        if config.github_reporting.pr_comments and pr_number:
            commenter = PRCommenter(config)
            url = commenter.post_or_update(owner, repo, pr_number, triage)
            if url:
                result["pr_comment_url"] = url

        # Issue creation for critical findings
        if config.github_reporting.create_issues:
            result["issues_created"] = self._create_issues(triage, config, owner, repo)

        return result

    def _create_issues(self, triage: TriageResult, config: AppConfig, owner: str, repo: str) -> list[str]:
        """Create GitHub issues for findings at or above the configured severity threshold."""
        threshold = Severity.from_str(config.github_reporting.issue_severity)
        client = GitHubClient(config.github)
        created: list[str] = []

        for severity_key, findings in triage.findings.items():
            severity = Severity.from_str(severity_key)
            if severity > threshold:  # Skip lower severities
                continue

            for finding in findings:
                # Check for existing open issue with same fingerprint
                fingerprint_tag = f"[{finding.fingerprint[:8]}]" if finding.fingerprint else ""
                search_term = fingerprint_tag or finding.title[:50]

                existing = client.find_existing_issue(owner, repo, search_term)
                if existing:
                    log.debug("Issue already exists for %s: %s", finding.title, existing.get("html_url"))
                    continue

                title = f"[Security] {severity_key}: {finding.title[:80]} {fingerprint_tag}"
                body = (
                    f"## Security Finding\n\n"
                    f"**Severity:** {severity_key}\n"
                    f"**Scanner:** {finding.scanner}\n"
                    f"**Fingerprint:** `{finding.fingerprint}`\n\n"
                    f"### Description\n{finding.description}\n\n"
                    f"### Recommendation\n{finding.recommendation}\n\n"
                    f"---\n<sub>Auto-created by secaudit</sub>"
                )

                try:
                    issue = client.create_issue(
                        owner,
                        repo,
                        title,
                        body,
                        labels=config.github_reporting.issue_labels,
                        assignees=config.github_reporting.issue_assignees or None,
                    )
                    url = issue.get("html_url", "")
                    log.info("Created issue: %s", url)
                    created.append(url)
                except Exception as e:
                    log.error("Failed to create issue for %s: %s", finding.title, e)

        return created
