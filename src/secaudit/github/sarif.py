"""SARIF upload to GitHub Security tab via the code scanning API."""

from __future__ import annotations

import base64
import gzip
import json
import logging

import requests

from secaudit.config import AppConfig
from secaudit.utils.retry import retry

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


@retry(max_attempts=3, base_delay=2.0, exceptions=(requests.RequestException,))
def upload_sarif(
    owner: str,
    repo: str,
    sarif_content: str,
    commit_sha: str,
    ref: str,
    config: AppConfig,
) -> bool:
    """Upload SARIF to GitHub code scanning API.

    Args:
        owner: Repository owner.
        repo: Repository name.
        sarif_content: SARIF JSON string.
        commit_sha: The commit SHA to associate results with.
        ref: The git ref (e.g., refs/heads/main).
        config: App config with GitHub token.

    Returns:
        True on success, False on failure.
    """
    if not config.github.token:
        log.warning("No GitHub token configured, skipping SARIF upload")
        return False

    # SARIF must be gzipped and base64-encoded for the API
    compressed = gzip.compress(sarif_content.encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("ascii")

    headers = {
        "Authorization": f"Bearer {config.github.token}",
        "Accept": "application/vnd.github+json",
    }

    resp = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/code-scanning/sarifs",
        headers=headers,
        json={
            "commit_sha": commit_sha,
            "ref": ref,
            "sarif": encoded,
        },
        timeout=60,
    )

    if resp.status_code in (200, 202):
        log.info("SARIF uploaded to %s/%s", owner, repo)
        return True

    log.warning("SARIF upload failed: %d %s", resp.status_code, resp.text[:200])
    return False
