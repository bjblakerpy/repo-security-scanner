"""GitHub API client — repo discovery, cloning, PR info."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

import requests

from secaudit.config import GithubConfig
from secaudit.models import RepoTarget
from secaudit.utils.retry import retry

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubClient:
    """Thin wrapper around GitHub REST API v3."""

    def __init__(self, config: GithubConfig):
        self.config = config
        self._session = requests.Session()
        if config.token:
            self._session.headers["Authorization"] = f"Bearer {config.token}"
        self._session.headers["Accept"] = "application/vnd.github+json"
        self._session.headers["X-GitHub-Api-Version"] = "2022-11-28"

    @retry(max_attempts=3, base_delay=1.0, exceptions=(requests.RequestException,))
    def _get(self, path: str, params: dict | None = None) -> dict | list:
        resp = self._session.get(f"{GITHUB_API}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    @retry(max_attempts=3, base_delay=1.0, exceptions=(requests.RequestException,))
    def _post(self, path: str, json_data: dict) -> dict:
        resp = self._session.post(f"{GITHUB_API}{path}", json=json_data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def list_org_repos(self) -> list[RepoTarget]:
        """List all repos in the configured org."""
        org = self.config.org
        if not org:
            return []

        repos: list[RepoTarget] = []
        page = 1
        while True:
            data = self._get(f"/orgs/{org}/repos", params={
                "per_page": 100,
                "page": page,
                "type": "all",
                "sort": "updated",
            })
            if not data:
                break

            for repo in data:
                # Skip forks if configured
                if repo.get("fork") and not self.config.include_forks:
                    continue
                # Skip excluded repos
                full_name = repo.get("full_name", "")
                if full_name in self.config.exclude_repos or repo.get("name") in self.config.exclude_repos:
                    continue
                # Skip archived repos
                if repo.get("archived"):
                    continue

                repos.append(RepoTarget(
                    name=full_name,
                    url=repo.get("clone_url", ""),
                    owner=org,
                    repo_name=repo.get("name", ""),
                ))

            page += 1

        log.info("Found %d repos in org %s", len(repos), org)
        return repos

    def clone_repo(self, target: RepoTarget, shallow: bool = True) -> Path:
        """Clone a repo to a temp directory. Returns the path.

        The caller is responsible for cleanup.
        """
        dest = Path(tempfile.mkdtemp(prefix=f"secaudit-{target.repo_name}-"))
        clone_url = target.url

        # Use token auth for private repos
        if self.config.token and clone_url and "github.com" in clone_url:
            clone_url = clone_url.replace(
                "https://github.com",
                f"https://x-access-token:{self.config.token}@github.com",
            )

        cmd = ["git", "clone"]
        if shallow:
            cmd.extend(["--depth", str(max(self.config.clone_depth, 1))])
        if target.ref:
            cmd.extend(["--branch", target.ref])
        cmd.extend([clone_url, str(dest)])

        log.info("Cloning %s to %s (shallow=%s)", target.name, dest, shallow)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            log.error("Failed to clone %s: %s", target.name, result.stderr[:300])
            raise RuntimeError(f"Git clone failed for {target.name}: {result.stderr[:300]}")

        target.path = dest
        return dest

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        """Get PR metadata."""
        return self._get(f"/repos/{owner}/{repo}/pulls/{pr_number}")

    def get_changed_files(self, owner: str, repo: str, pr_number: int) -> list[str]:
        """Get list of files changed in a PR."""
        files = self._get(f"/repos/{owner}/{repo}/pulls/{pr_number}/files", params={"per_page": 100})
        return [f.get("filename", "") for f in files]

    def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
        assignees: list[str] | None = None,
    ) -> dict:
        """Create a GitHub issue."""
        data = {"title": title, "body": body}
        if labels:
            data["labels"] = labels
        if assignees:
            data["assignees"] = assignees
        return self._post(f"/repos/{owner}/{repo}/issues", data)

    def find_existing_issue(self, owner: str, repo: str, search_term: str) -> dict | None:
        """Find an existing open issue by search term in title."""
        issues = self._get(f"/repos/{owner}/{repo}/issues", params={
            "state": "open",
            "per_page": 100,
        })
        for issue in issues:
            if search_term in issue.get("title", ""):
                return issue
        return None
