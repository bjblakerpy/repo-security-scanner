"""Configuration loading — YAML files with env var interpolation."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def _interpolate_env(value: str) -> str:
    """Replace ${ENV_VAR} references with their values."""

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return ENV_VAR_PATTERN.sub(_replace, value)


def _walk_and_interpolate(obj: dict | list | str) -> dict | list | str:
    """Recursively interpolate env vars in config values."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    return obj


@dataclass
class GithubConfig:
    token: str = ""
    org: str = ""
    repos: list[str] = field(default_factory=list)
    exclude_repos: list[str] = field(default_factory=list)
    include_forks: bool = False
    clone_depth: int = 1  # 0 = full clone


@dataclass
class TriageConfig:
    enabled: bool = True
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    max_findings: int = 500


@dataclass
class NotionConfig:
    enabled: bool = False
    token: str = ""
    database_id: str = ""
    deduplicate: bool = True


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to: list[str] = field(default_factory=list)
    send_on: str = "all"  # all | findings_only | critical_only


@dataclass
class GithubReportingConfig:
    pr_comments: bool = True
    create_issues: bool = True
    issue_severity: str = "CRITICAL"
    issue_assignees: list[str] = field(default_factory=list)
    issue_labels: list[str] = field(default_factory=lambda: ["security", "automated"])
    sarif_upload: bool = True


@dataclass
class PersistenceConfig:
    enabled: bool = True
    db_path: str = "~/.secaudit/findings.db"
    deduplicate_notifications: bool = True
    retention_days: int = 365


@dataclass
class AppConfig:
    """Top-level application config."""

    github: GithubConfig = field(default_factory=GithubConfig)
    scanners: dict = field(default_factory=lambda: {"enabled": []})
    triage: TriageConfig = field(default_factory=TriageConfig)
    notion: NotionConfig = field(default_factory=NotionConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    github_reporting: GithubReportingConfig = field(default_factory=GithubReportingConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    severity_threshold: str = "LOW"
    log_level: str = "INFO"
    output_path: str = ""


def _build_config_from_dict(raw: dict) -> AppConfig:
    """Convert a raw config dict into an AppConfig dataclass."""
    config = AppConfig()

    # GitHub
    gh = raw.get("github", {})
    config.github = GithubConfig(
        token=gh.get("token", os.environ.get("GITHUB_TOKEN", "")),
        org=gh.get("org", ""),
        repos=gh.get("repos", []),
        exclude_repos=gh.get("exclude_repos", []),
        include_forks=gh.get("include_forks", False),
        clone_depth=gh.get("clone_depth", 1),
    )

    # Scanners (pass through as dict — scanner-specific config)
    config.scanners = raw.get("scanners", {"enabled": []})

    # Triage
    tr = raw.get("triage", {})
    config.triage = TriageConfig(
        enabled=tr.get("enabled", True),
        model=tr.get("model", "claude-sonnet-4-20250514"),
        api_key=tr.get("api_key", os.environ.get("ANTHROPIC_API_KEY", "")),
        max_findings=tr.get("max_findings", 500),
    )

    # Notion
    notion = raw.get("reporting", {}).get("notion", raw.get("notion", {}))
    config.notion = NotionConfig(
        enabled=notion.get("enabled", bool(os.environ.get("NOTION_TOKEN"))),
        token=notion.get("token", os.environ.get("NOTION_TOKEN", "")),
        database_id=notion.get("database_id", os.environ.get("NOTION_DATABASE_ID", "")),
        deduplicate=notion.get("deduplicate", True),
    )

    # Email
    em = raw.get("reporting", {}).get("email", raw.get("email", {}))
    to_list = em.get("to", os.environ.get("EMAIL_TO", ""))
    if isinstance(to_list, str):
        to_list = [addr.strip() for addr in to_list.split(",") if addr.strip()]
    config.email = EmailConfig(
        enabled=em.get("enabled", bool(os.environ.get("SMTP_USER"))),
        smtp_host=em.get("smtp_host", os.environ.get("SMTP_HOST", "smtp.gmail.com")),
        smtp_port=int(em.get("smtp_port", os.environ.get("SMTP_PORT", "587"))),
        username=em.get("username", os.environ.get("SMTP_USER", "")),
        password=em.get("password", os.environ.get("SMTP_PASS", "")),
        from_addr=em.get("from", os.environ.get("EMAIL_FROM", os.environ.get("SMTP_USER", ""))),
        to=to_list,
        send_on=em.get("send_on", "all"),
    )

    # GitHub Reporting
    ghr = raw.get("reporting", {}).get("github", {})
    config.github_reporting = GithubReportingConfig(
        pr_comments=ghr.get("pr_comments", True),
        create_issues=ghr.get("create_issues", True),
        issue_severity=ghr.get("issue_severity", "CRITICAL"),
        issue_assignees=ghr.get("issue_assignees", []),
        issue_labels=ghr.get("issue_labels", ["security", "automated"]),
        sarif_upload=ghr.get("sarif_upload", True),
    )

    # Persistence
    pers = raw.get("persistence", {})
    config.persistence = PersistenceConfig(
        enabled=pers.get("enabled", True),
        db_path=pers.get("db_path", "~/.secaudit/findings.db"),
        deduplicate_notifications=pers.get("deduplicate_notifications", True),
        retention_days=pers.get("retention_days", 365),
    )

    config.severity_threshold = raw.get("severity_threshold", "LOW")
    config.log_level = raw.get("logging", {}).get("level", "INFO")
    config.output_path = raw.get("output_path", "")

    return config


def load_config(
    config_path: str | Path | None = None,
    cli_overrides: dict | None = None,
) -> AppConfig:
    """Load config from YAML file, env vars, and CLI overrides.

    Merge precedence: defaults < config file < env vars < CLI args
    """
    raw: dict = {}

    # Load YAML if provided
    if config_path:
        path = Path(config_path)
        if path.exists():
            log.info("Loading config from %s", path)
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
            raw = _walk_and_interpolate(raw)
        else:
            log.warning("Config file not found: %s, using defaults", path)

    config = _build_config_from_dict(raw)

    # Apply CLI overrides
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None and hasattr(config, key):
                setattr(config, key, value)

    return config
