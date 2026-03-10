"""Tests for config loading."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from secaudit.config import load_config


def test_load_defaults():
    """Loading with no config file returns sensible defaults."""
    config = load_config()
    assert config.severity_threshold == "LOW"
    assert config.triage.enabled is True
    assert config.persistence.enabled is True


def test_load_yaml_file(tmp_path):
    """Config values from YAML override defaults."""
    config_file = tmp_path / "secaudit.yml"
    config_file.write_text("""
severity_threshold: HIGH
triage:
  enabled: false
  model: claude-sonnet-4-20250514
github:
  org: test-org
  include_forks: true
""")
    config = load_config(str(config_file))
    assert config.severity_threshold == "HIGH"
    assert config.triage.enabled is False
    assert config.github.org == "test-org"
    assert config.github.include_forks is True


def test_env_var_interpolation(tmp_path):
    """${VAR} in YAML is replaced with env var value."""
    config_file = tmp_path / "secaudit.yml"
    config_file.write_text("""
triage:
  api_key: ${TEST_SECAUDIT_KEY}
""")
    with patch.dict(os.environ, {"TEST_SECAUDIT_KEY": "sk-test-123"}):
        config = load_config(str(config_file))
    assert config.triage.api_key == "sk-test-123"


def test_missing_config_file():
    """Missing config file uses defaults without error."""
    config = load_config("/nonexistent/path.yml")
    assert config.severity_threshold == "LOW"


def test_cli_overrides():
    """CLI overrides take precedence."""
    config = load_config(cli_overrides={"severity_threshold": "CRITICAL"})
    assert config.severity_threshold == "CRITICAL"


def test_email_to_string_parsing(tmp_path):
    """EMAIL_TO env var with commas is parsed into list."""
    with patch.dict(os.environ, {
        "SMTP_USER": "user@test.com",
        "EMAIL_TO": "a@test.com, b@test.com, c@test.com",
    }):
        config = load_config()
    assert config.email.to == ["a@test.com", "b@test.com", "c@test.com"]
