"""Core pipeline orchestrator — replaces the old run_agent() function.

Pipeline: resolve repos -> clone if needed -> scan -> triage -> dedup -> report
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path

from secaudit.config import AppConfig
from secaudit.github.client import GitHubClient
from secaudit.models import Finding, RepoTarget, Severity, TriageResult
from secaudit.persistence.dedup import deduplicate_and_persist
from secaudit.persistence.store import FindingStore
from secaudit.reporters.email import EmailReporter
from secaudit.reporters.github_reporter import GitHubReporter
from secaudit.reporters.json_export import JsonExportReporter
from secaudit.reporters.notion import NotionReporter
from secaudit.reporters.sarif_reporter import SarifReporter
from secaudit.scanners import get_all_scanners, get_scanner
from secaudit.triager.claude import triage_findings

log = logging.getLogger(__name__)


def resolve_targets(config: AppConfig, cli_repos: list[str] | None = None, cli_org: str | None = None) -> list[RepoTarget]:
    """Build the list of repos to scan from config, CLI args, or GitHub org."""
    targets: list[RepoTarget] = []

    # CLI repos take precedence
    if cli_repos:
        for spec in cli_repos:
            targets.append(RepoTarget.from_spec(spec))
        return targets

    # CLI org takes precedence over config
    org = cli_org or config.github.org
    if org:
        gh_config = config.github
        if cli_org:
            gh_config.org = cli_org
        client = GitHubClient(gh_config)
        targets = client.list_org_repos()
        return targets

    # Config repos
    if config.github.repos:
        for spec in config.github.repos:
            targets.append(RepoTarget.from_spec(spec))
        return targets

    # Default: current directory
    targets.append(RepoTarget.from_path("."))
    return targets


def run_scanners(
    repo_path: Path,
    config: AppConfig,
    scanner_names: list[str] | None = None,
) -> list[Finding]:
    """Run all applicable scanners against a repo."""
    if scanner_names:
        scanners = [get_scanner(name) for name in scanner_names]
    else:
        enabled = config.scanners.get("enabled", [])
        if enabled:
            scanners = [get_scanner(name) for name in enabled]
        else:
            scanners = get_all_scanners()

    all_findings: list[Finding] = []

    for scanner in scanners:
        if not scanner.is_available():
            log.warning("Scanner %s is not installed, skipping", scanner.name)
            continue
        if not scanner.is_applicable(repo_path):
            log.debug("Scanner %s not applicable to %s, skipping", scanner.name, repo_path)
            continue

        log.info("Running scanner: %s", scanner.name)
        scanner_config = config.scanners.get(scanner.name, {})
        try:
            result = scanner.scan(repo_path, scanner_config)
            if result.error:
                log.warning("Scanner %s reported error: %s", scanner.name, result.error)
            all_findings.extend(result.findings)
            log.info("  %s: %d findings (%.1fs)", scanner.name, len(result.findings), result.duration_seconds)
        except Exception as e:
            log.error("Scanner %s crashed: %s", scanner.name, e)

    return all_findings


def run_reporters(
    triage: TriageResult,
    config: AppConfig,
    **kwargs,
) -> dict:
    """Run all configured reporters."""
    results = {}

    # Notion
    if config.notion.enabled:
        notion = NotionReporter()
        results["notion"] = notion.report(triage, config, **kwargs)

    # Email
    if config.email.enabled:
        email = EmailReporter()
        notion_urls = results.get("notion", {}).get("urls", {})
        results["email"] = email.report(triage, config, notion_urls=notion_urls, **kwargs)

    # GitHub (PR comments + issues)
    if config.github.token and (config.github_reporting.pr_comments or config.github_reporting.create_issues):
        gh_reporter = GitHubReporter()
        results["github"] = gh_reporter.report(triage, config, **kwargs)

    return results


def scan_repo(
    target: RepoTarget,
    config: AppConfig,
    scanner_names: list[str] | None = None,
    no_triage: bool = False,
    no_notify: bool = False,
    pr_number: int | None = None,
    output_format: str | None = None,
    output_file: str | None = None,
) -> TriageResult:
    """Full scan pipeline for a single repo."""
    start = time.time()
    gh_client = GitHubClient(config.github) if config.github.token else None
    cloned_path: Path | None = None

    try:
        # Resolve repo path
        if target.path and target.path.exists():
            repo_path = target.path
        elif target.url and gh_client:
            # Gitleaks needs full history
            needs_full = not scanner_names or "gitleaks" in (scanner_names or [])
            cloned_path = gh_client.clone_repo(target, shallow=not needs_full)
            repo_path = cloned_path
        else:
            log.error("Cannot resolve repo: %s", target.name)
            return TriageResult(summary=f"Failed to resolve repo: {target.name}", findings={}, raw_count=0, triaged_count=0)

        log.info("Scanning %s at %s", target.name, repo_path)

        # Run scanners
        findings = run_scanners(repo_path, config, scanner_names)
        log.info("Raw findings for %s: %d", target.name, len(findings))

        # Filter by severity threshold
        threshold = Severity.from_str(config.severity_threshold)
        findings = [f for f in findings if f.severity <= threshold]

        # Triage
        if no_triage or not config.triage.enabled:
            from secaudit.triager.claude import _passthrough_triage
            triage = _passthrough_triage(findings)
        else:
            triage = triage_findings(findings, config.triage)

        log.info("Triaged findings for %s: %d", target.name, triage.triaged_count)

        # Persistence & dedup
        if config.persistence.enabled:
            store = FindingStore(config.persistence.db_path)
            try:
                triage = deduplicate_and_persist(
                    triage, target.name, store,
                    notify_new_only=config.persistence.deduplicate_notifications,
                )
                scanners_used = ",".join(scanner_names) if scanner_names else "all"
                store.record_scan(target.name, time.time() - start, triage.triaged_count, scanners_used)
            finally:
                store.close()

        # Write output file
        if output_format or output_file:
            fmt = output_format or "json"
            path = output_file or config.output_path
            if fmt == "sarif":
                SarifReporter().report(triage, config, output_path=path or "results.sarif")
            else:
                JsonExportReporter().report(triage, config, output_path=path, format=fmt)

        # Also write triage result JSON for CI gate checks
        triage_output = Path(config.output_path or "scan-results.json")
        triage_output.write_text(json.dumps(triage.to_dict(), indent=2))

        # Report
        if not no_notify:
            run_reporters(
                triage,
                config,
                repo_name=target.name,
                owner=target.owner,
                repo=target.repo_name,
                pr_number=pr_number,
            )

        return triage

    finally:
        # Clean up cloned repo
        if cloned_path and cloned_path.exists():
            shutil.rmtree(cloned_path, ignore_errors=True)


def run(
    config: AppConfig,
    repos: list[str] | None = None,
    org: str | None = None,
    scanner_names: list[str] | None = None,
    no_triage: bool = False,
    no_notify: bool = False,
    pr_number: int | None = None,
    output_format: str | None = None,
    output_file: str | None = None,
) -> list[TriageResult]:
    """Main entry point — scan one or more repos."""
    targets = resolve_targets(config, repos, org)
    log.info("Scanning %d repo(s)", len(targets))

    results: list[TriageResult] = []
    for target in targets:
        log.info("=" * 60)
        log.info("Repo: %s", target.name)
        log.info("=" * 60)
        result = scan_repo(
            target,
            config,
            scanner_names=scanner_names,
            no_triage=no_triage,
            no_notify=no_notify,
            pr_number=pr_number,
            output_format=output_format,
            output_file=output_file,
        )
        results.append(result)

    # Summary
    total_findings = sum(r.triaged_count for r in results)
    has_critical = any(r.has_critical for r in results)
    log.info("Scan complete: %d repo(s), %d total findings, critical=%s", len(results), total_findings, has_critical)

    return results
