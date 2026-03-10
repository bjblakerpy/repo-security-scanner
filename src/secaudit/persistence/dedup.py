"""Cross-run deduplication logic."""

from __future__ import annotations

import logging

from secaudit.models import Finding, TriageResult
from secaudit.persistence.store import FindingStore

log = logging.getLogger(__name__)


def deduplicate_and_persist(
    triage: TriageResult,
    repo: str,
    store: FindingStore,
    notify_new_only: bool = True,
) -> TriageResult:
    """Persist findings and optionally filter to new-only for notifications.

    Args:
        triage: The triage result to process.
        repo: Repository identifier.
        store: The SQLite finding store.
        notify_new_only: If True, return only new findings in the result.

    Returns:
        A new TriageResult, potentially filtered to new findings only.
    """
    all_fingerprints: set[str] = set()
    new_findings: dict[str, list[Finding]] = {}
    new_count = 0
    total_count = 0

    for severity_key, findings in triage.findings.items():
        new_findings[severity_key] = []
        for finding in findings:
            total_count += 1
            if finding.fingerprint:
                all_fingerprints.add(finding.fingerprint)

            # Check if suppressed
            if finding.fingerprint and store.is_suppressed(finding.fingerprint, repo):
                log.debug("Skipping suppressed finding: %s", finding.title)
                continue

            is_new = store.upsert_finding(finding, repo)
            if is_new:
                new_findings[severity_key].append(finding)
                new_count += 1
            elif not notify_new_only:
                new_findings[severity_key].append(finding)

    # Mark findings not seen in this run as resolved
    resolved = store.mark_resolved(repo, all_fingerprints)
    if resolved:
        log.info("Marked %d findings as resolved in %s", resolved, repo)

    log.info("Dedup: %d total, %d new, %d resolved", total_count, new_count, resolved)

    if notify_new_only:
        return TriageResult(
            summary=triage.summary,
            findings=new_findings,
            raw_count=triage.raw_count,
            triaged_count=new_count,
        )

    return TriageResult(
        summary=triage.summary,
        findings=new_findings,
        raw_count=triage.raw_count,
        triaged_count=total_count,
    )
