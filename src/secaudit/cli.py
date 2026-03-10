"""CLI interface — click-based with scan, scanners, and report subcommands."""

from __future__ import annotations

import logging
import sys

import click

from secaudit import __version__
from secaudit.config import load_config


@click.group()
@click.version_option(version=__version__, prog_name="secaudit")
def main():
    """Security scanning tool for GitHub repositories."""
    pass


@main.command()
@click.option("--repo", multiple=True, help="Repo to scan (path or GitHub URL). Repeatable.")
@click.option("--org", default=None, help="Scan all repos in a GitHub org.")
@click.option("--repos-file", type=click.Path(exists=True), help="File with one repo per line.")
@click.option("--config", "config_path", default=None, type=click.Path(), help="Config file path.")
@click.option("--scanner", multiple=True, help="Run only these scanners. Repeatable.")
@click.option("--output", "output_format", type=click.Choice(["table", "json", "csv", "sarif"]), default=None, help="Output format.")
@click.option("--output-file", default=None, help="Write results to file.")
@click.option("--severity", default=None, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Minimum severity to report.")
@click.option("--no-triage", is_flag=True, help="Skip Claude triage, report raw findings.")
@click.option("--no-notify", is_flag=True, help="Skip all notifications (Notion, email, GitHub).")
@click.option("--pr-number", type=int, default=None, help="Associate scan with a GitHub PR.")
@click.option("-v", "--verbose", is_flag=True, help="Debug logging.")
def scan(
    repo,
    org,
    repos_file,
    config_path,
    scanner,
    output_format,
    output_file,
    severity,
    no_triage,
    no_notify,
    pr_number,
    verbose,
):
    """Run security scans against one or more repos."""
    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")

    # Find config file
    if not config_path:
        for candidate in ("secaudit.yml", "secaudit.yaml", ".secaudit.yml"):
            import os
            if os.path.exists(candidate):
                config_path = candidate
                break

    # Build config
    overrides = {}
    if severity:
        overrides["severity_threshold"] = severity

    config = load_config(config_path, overrides)

    # Repos from file
    repos_list = list(repo) if repo else None
    if repos_file:
        with open(repos_file) as f:
            repos_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    scanner_names = list(scanner) if scanner else None

    # Run
    from secaudit.orchestrator import run as run_scan

    results = run_scan(
        config=config,
        repos=repos_list,
        org=org,
        scanner_names=scanner_names,
        no_triage=no_triage,
        no_notify=no_notify,
        pr_number=pr_number,
        output_format=output_format,
        output_file=output_file,
    )

    # Exit code: 1 if critical findings and PR mode
    has_critical = any(r.has_critical for r in results)
    if has_critical and pr_number:
        click.echo(f"CRITICAL findings detected — failing PR gate.", err=True)
        sys.exit(1)

    # Also exit 1 if critical and output format is set (CI mode)
    if has_critical and output_format:
        sys.exit(1)

    # Print table summary to stdout if no output format
    if not output_format:
        _print_summary(results)


@main.command()
def scanners():
    """List available scanners and their status."""
    from secaudit.scanners import get_all_scanners

    click.echo(f"{'Scanner':<15} {'Available':<12} Description")
    click.echo(f"{'─' * 15} {'─' * 12} {'─' * 45}")

    for s in get_all_scanners():
        available = "Yes" if s.is_available() else "No (install)"
        click.echo(f"{s.name:<15} {available:<12} {s.description}")


@main.command()
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json", help="Output format.")
@click.option("--since", default=None, help="Date filter (YYYY-MM-DD).")
@click.option("--repo", default=None, help="Filter by repo name.")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--status", default="open", help="Filter by status (open/resolved/suppressed).")
@click.option("--trend", is_flag=True, help="Show scan history trend.")
@click.option("--config", "config_path", default=None, type=click.Path(), help="Config file path.")
def report(fmt, since, repo, severity, status, trend, config_path):
    """Generate reports from stored scan results."""
    import json

    config = load_config(config_path)

    if not config.persistence.enabled:
        click.echo("Persistence is disabled. Enable it in config to use reports.", err=True)
        sys.exit(1)

    from secaudit.persistence.store import FindingStore

    store = FindingStore(config.persistence.db_path)

    if trend:
        history = store.get_scan_history(repo=repo)
        click.echo(json.dumps(history, indent=2))
    else:
        findings = store.get_findings(repo=repo, severity=severity, status=status, since=since)
        if fmt == "json":
            click.echo(json.dumps(findings, indent=2))
        else:
            # CSV
            import csv
            import io
            output = io.StringIO()
            if findings:
                writer = csv.DictWriter(output, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
            click.echo(output.getvalue())

    store.close()


def _print_summary(results):
    """Print a table summary of scan results."""
    for result in results:
        total = result.total_findings
        counts = {s: len(result.findings.get(s, [])) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

        click.echo(f"\n{result.summary}")
        click.echo(f"  CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}  Total: {total}")

        if total == 0:
            click.echo("  No findings.")
            continue

        click.echo(f"\n  {'Severity':<10} {'Scanner':<12} Finding")
        click.echo(f"  {'─' * 10} {'─' * 12} {'─' * 50}")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            for f in result.findings.get(sev, []):
                click.echo(f"  {sev:<10} {f.scanner:<12} {f.title[:60]}")
