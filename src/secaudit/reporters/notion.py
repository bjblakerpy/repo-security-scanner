"""Notion reporter — creates finding pages in a Notion database with dedup and rate limiting."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from secaudit.config import AppConfig
from secaudit.models import Finding, TriageResult
from secaudit.reporters.base import BaseReporter
from secaudit.utils.rate_limiter import RateLimiter
from secaudit.utils.retry import retry

log = logging.getLogger(__name__)

NOTION_API = "https://api.notion.com/v1"
_limiter = RateLimiter(max_per_second=3.0)  # Notion API limit: 3 requests/second


def _notion_headers(token: str) -> dict:
    """Build auth headers for the Notion API."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }


def _severity_select(severity: str) -> str:
    return severity.upper() if severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "LOW"


@retry(max_attempts=3, base_delay=2.0, exceptions=(requests.RequestException,))
def _create_page(headers: dict, database_id: str, finding: Finding, severity: str) -> str | None:
    """Create a single finding page in Notion."""
    _limiter.wait()

    payload = {
        "parent": {"database_id": database_id},
        "properties": {
            "Title": {
                "title": [{"text": {"content": finding.title[:100]}}]
            },
            "Severity": {
                "select": {"name": _severity_select(severity)}
            },
            "Scanner": {
                "rich_text": [{"text": {"content": finding.scanner}}]
            },
            "Status": {
                "select": {"name": "Open"}
            },
            "Date Found": {
                "date": {"start": datetime.now(timezone.utc).date().isoformat()}
            },
        },
        "children": [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"type": "text", "text": {"content": finding.description[:2000]}}]
                },
            },
            {
                "object": "block",
                "type": "callout",
                "callout": {
                    "rich_text": [
                        {"type": "text", "text": {"content": f"Recommendation: {finding.recommendation[:2000]}"}}
                    ],
                    "icon": {"emoji": "\U0001f527"},
                },
            },
        ],
    }

    resp = requests.post(f"{NOTION_API}/pages", headers=headers, json=payload, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("url")
    log.warning("Notion page creation failed: %d %s", resp.status_code, resp.text[:200])
    if resp.status_code == 429:
        raise requests.RequestException("Rate limited by Notion API")
    return None


def _check_existing(headers: dict, database_id: str, fingerprint: str) -> bool:
    """Check if a finding with this fingerprint already exists in Notion."""
    _limiter.wait()
    payload = {
        "filter": {
            "property": "Title",
            "title": {"contains": fingerprint[:8]},
        },
        "page_size": 1,
    }
    try:
        resp = requests.post(
            f"{NOTION_API}/databases/{database_id}/query",
            headers=headers,
            json=payload,
            timeout=15,
        )
        if resp.status_code == 200:
            return len(resp.json().get("results", [])) > 0
    except requests.RequestException:
        pass
    return False


class NotionReporter(BaseReporter):
    """Creates Notion database pages for each finding.

    Features rate limiting (3 req/s per Notion API limits), retry on 429,
    and fingerprint-based deduplication to avoid creating duplicate pages
    on repeated scans. Requires notion.token and notion.database_id in config.

    Returns dict with 'urls' mapping severity -> list of created page URLs.
    """

    name = "notion"

    def report(self, triage: TriageResult, config: AppConfig, **kwargs) -> dict:
        if not config.notion.enabled or not config.notion.token or not config.notion.database_id:
            log.warning("Notion not configured, skipping.")
            return {"urls": {}}

        headers = _notion_headers(config.notion.token)
        urls: dict[str, list[str]] = {}

        for severity_key, findings in triage.findings.items():
            urls[severity_key] = []
            for finding in findings:
                # Dedup: skip if a page with this fingerprint already exists
                if config.notion.deduplicate and finding.fingerprint:
                    if _check_existing(headers, config.notion.database_id, finding.fingerprint):
                        log.debug("Skipping duplicate Notion page for %s", finding.title)
                        continue

                url = _create_page(headers, config.notion.database_id, finding, severity_key)
                if url:
                    urls[severity_key].append(url)

        total = sum(len(v) for v in urls.values())
        log.info("Created %d Notion pages", total)
        return {"urls": urls}
