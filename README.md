# secaudit

Multi-repo GitHub security scanning tool with Claude-powered triage.

- Scans repos for secrets, SAST issues, vulnerable dependencies, IaC misconfigs, Dockerfile issues, and license violations
- Triages findings through Claude (deduplicates noise, prioritizes risk)
- Reports to GitHub (PR comments, issues, SARIF/Security tab), Notion, and email
- Tracks findings across runs with SQLite deduplication
- Scans entire GitHub orgs or individual repos

---

## Scanners

| Scanner | What it catches |
|---|---|
| `gitleaks` | Secrets / credentials in full git history |
| `semgrep` | SAST: injection, XSS, insecure patterns |
| `pip-audit` | Python dependency CVEs |
| `npm-audit` | Node.js dependency CVEs |
| `trivy` | Container image and filesystem vulnerabilities |
| `checkov` | IaC misconfigurations (Terraform, CloudFormation, K8s) |
| `hadolint` | Dockerfile best practices |
| `licenses` | Copyleft / restricted license detection |

---

## Quick Start

### 1. Install

```bash
pip install .

# Install scanner tools
brew install gitleaks hadolint trivy   # macOS
pip install pip-audit semgrep checkov
```

### 2. Configure

```bash
cp config.example.yml secaudit.yml
# Edit secaudit.yml with your settings

# Or use environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
export GITHUB_TOKEN="ghp_..."
```

### 3. Run

```bash
# Scan current directory
secaudit scan

# Scan a GitHub repo
secaudit scan --repo owner/repo-name

# Scan an entire org
secaudit scan --org my-org

# Scan with specific scanners only
secaudit scan --scanner gitleaks --scanner semgrep

# Output SARIF for GitHub Security tab
secaudit scan --output sarif --output-file results.sarif

# Skip Claude triage (faster, raw findings)
secaudit scan --no-triage

# List available scanners
secaudit scanners

# Query stored findings
secaudit report --repo owner/repo --severity CRITICAL
```

---

## CLI Reference

```
secaudit scan [OPTIONS]
  --repo TEXT         Repo to scan (path, URL, or owner/repo). Repeatable.
  --org TEXT          Scan all repos in a GitHub org.
  --repos-file PATH  File with one repo per line.
  --config PATH      Config file path. [default: secaudit.yml]
  --scanner TEXT     Run only these scanners. Repeatable.
  --output FORMAT    Output format: table, json, csv, sarif.
  --output-file PATH Write results to file.
  --severity LEVEL   Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
  --no-triage        Skip Claude triage, report raw findings.
  --no-notify        Skip all notifications.
  --pr-number INT    Associate scan with a GitHub PR.
  -v, --verbose      Debug logging.

secaudit scanners     List available scanners and install status.

secaudit report [OPTIONS]
  --format TEXT       json or csv. [default: json]
  --since TEXT        Date filter (YYYY-MM-DD).
  --repo TEXT         Filter by repo name.
  --severity TEXT     Filter by severity.
  --status TEXT       open, resolved, or suppressed. [default: open]
  --trend             Show scan history over time.
```

---

## Configuration

Copy `config.example.yml` to `secaudit.yml`. All `${VAR}` references are resolved from environment variables.

Key sections:
- **github** — Token, org, repo list, clone settings
- **scanners** — Enable/disable scanners, per-scanner config
- **triage** — Claude model, API key, max findings
- **reporting** — Notion, email, GitHub (PR comments, issues, SARIF)
- **persistence** — SQLite dedup, retention

See [config.example.yml](config.example.yml) for all options.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For triage | Claude API key |
| `GITHUB_TOKEN` | For org scan / PR | GitHub personal access token |
| `NOTION_TOKEN` | For Notion | Notion integration token |
| `NOTION_DATABASE_ID` | For Notion | Notion database ID |
| `SMTP_USER` | For email | SMTP username |
| `SMTP_PASS` | For email | SMTP password (use app password) |
| `EMAIL_TO` | For email | Comma-separated recipient list |

---

## GitHub Actions

Two workflows are provided in `.github/workflows/`:

### Single-repo scan (`security-scan.yml`)

Runs on push, PR, weekly schedule, and manual trigger. Features:
- SARIF upload to GitHub Security tab
- PR comments with scan results
- Blocks PR merge on CRITICAL findings
- Caches scanner tools for faster runs

### Org-wide scan (`security-scan-org.yml`)

Scans all repos in an org on weekly schedule or manual trigger.

Add these **repository secrets**: `ANTHROPIC_API_KEY`, `GITHUB_TOKEN` (or `ORG_SCAN_TOKEN`), and optionally `NOTION_TOKEN`, `NOTION_DATABASE_ID`, `SMTP_*`, `EMAIL_*`.

---

## Notion Setup

Create a database with these properties:

| Property | Type |
|---|---|
| Title | Title |
| Severity | Select (CRITICAL, HIGH, MEDIUM, LOW) |
| Scanner | Text |
| Status | Select (Open, In Progress, Resolved) |
| Date Found | Date |

---

## Extending

To add a new scanner:

1. Create `src/secaudit/scanners/my_scanner.py`:

```python
from secaudit.scanners.base import BaseScanner
from secaudit.models import Finding, ScanResult, Severity

class MyScanner(BaseScanner):
    name = "my-scanner"
    description = "What it scans for"

    def is_available(self) -> bool:
        return self._check_tool("my-tool")

    def is_applicable(self, repo_path: Path) -> bool:
        return (repo_path / "relevant-file").exists()

    def scan(self, repo_path: Path, config: dict | None = None) -> ScanResult:
        # Run tool, parse output, return ScanResult with Finding objects
        ...
```

2. Add to registry in `src/secaudit/scanners/__init__.py`:

```python
from secaudit.scanners.my_scanner import MyScanner
# In _build_registry():
"my-scanner": MyScanner,
```

---

## How Deduplication Works

secaudit tracks findings across runs using a SQLite database (`~/.secaudit/findings.db`).

**Fingerprinting:** Each finding gets a stable fingerprint — a hash of `scanner + title + file_path + line + rule_id`. The same vulnerability produces the same fingerprint across runs, even if other details change.

**Cross-run behavior:**
- **New finding:** Inserted into the database, included in notifications
- **Existing finding:** Updated `last_seen` timestamp, skipped in notifications (configurable)
- **Missing finding:** If a previously-open finding is absent from the latest scan, it's marked `resolved`
- **Suppressed finding:** Manually set a finding's status to `suppressed` in the database to permanently ignore false positives

**Notification policy:** By default (`deduplicate_notifications: true`), only NEW findings trigger Notion pages, email alerts, and GitHub issues. Set to `false` to report all findings every run.

**Querying history:**

```bash
# Show all open critical findings
secaudit report --severity CRITICAL

# Show findings resolved in the last 30 days
secaudit report --status resolved --since 2025-01-01

# Show scan history trend
secaudit report --trend --repo owner/repo
```

---

## Sample Output

### CLI table output

```
2 critical/high findings require immediate attention.
  CRITICAL: 1  HIGH: 2  MEDIUM: 1  LOW: 0  Total: 4

  Severity   Scanner      Finding
  ────────── ──────────── ──────────────────────────────────────────────────
  CRITICAL   gitleaks     Secret detected: aws-access-key
  HIGH       semgrep      python.lang.security.audit.eval-detected
  HIGH       pip-audit    flask 2.0.0: CVE-2023-12345
  MEDIUM     npm-audit    lodash: prototype pollution
```

### JSON output (`--output json`)

```json
{
  "summary": "2 critical/high findings require immediate attention.",
  "raw_count": 15,
  "triaged_count": 4,
  "critical": [
    {
      "scanner": "gitleaks",
      "severity": "CRITICAL",
      "title": "Secret detected: aws-access-key",
      "description": "AWS Access Key found in config.py",
      "file_path": "config.py",
      "line": 42,
      "recommendation": "Rotate this credential and remove from git history",
      "fingerprint": "ef4ef329fd54a81d"
    }
  ],
  "high": [...],
  "medium": [...],
  "low": []
}
```

### PR comment

When `--pr-number` is set, secaudit posts a collapsible markdown comment on the PR:

> ## Security Scan Results
> **2 critical/high findings require immediate attention.**
>
> :red_circle: **1** CRITICAL | :orange_circle: **2** HIGH | :yellow_circle: **1** MEDIUM | :green_circle: **0** LOW
>
> <details><summary>CRITICAL (1)</summary>
>
> | Finding | Recommendation |
> |---|---|
> | **Secret detected: aws-access-key** | Rotate this credential immediately |
>
> </details>

---

## Troubleshooting

**Scanner not found:**
```
WARNING Scanner gitleaks is not installed, skipping
```
Install the missing tool. Run `secaudit scanners` to see what's installed.

**No findings reported:**
If scanners run but produce no findings, this is normal for clean repos. Use `-v` for debug output to confirm scanners actually executed.

**Claude triage fails:**
Ensure `ANTHROPIC_API_KEY` is set and valid. Use `--no-triage` to bypass triage and get raw scanner output.

**Notion page creation fails (429):**
The built-in rate limiter handles this automatically with retry. If it persists, reduce the number of findings sent to Notion by raising `severity_threshold`.

**GitHub PR comment not appearing:**
- Ensure `GITHUB_TOKEN` has `pull-requests: write` permission
- Check that `--pr-number` matches an open PR
- The token must have access to the target repository

**Org scan times out:**
Large orgs may exceed the default timeout. Increase `timeout-minutes` in the GitHub Actions workflow, or use `exclude_repos` in config to skip large/archived repos.

**SQLite database locked:**
Only one secaudit process should write to the database at a time. If running concurrent scans, use separate `db_path` values per scan or disable persistence with `persistence.enabled: false`.

**Gmail SMTP authentication:**
Use an App Password, not your account password:
1. Enable 2FA on your Google account
2. Go to myaccount.google.com > Security > App Passwords
3. Generate a password for "Mail"
4. Use that as `SMTP_PASS`

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Project Structure

```
src/secaudit/
├── cli.py              # Click CLI
├── config.py           # YAML + env var config
├── models.py           # Finding, ScanResult, TriageResult, RepoTarget
├── orchestrator.py     # Scan pipeline coordinator
├── github/             # GitHub API client, PR comments, SARIF upload
├── scanners/           # 8 scanner plugins (BaseScanner interface)
├── triager/            # Claude-powered triage
├── reporters/          # Notion, email, GitHub, JSON/CSV, SARIF
├── persistence/        # SQLite store, cross-run dedup
└── utils/              # Retry, rate limiter, subprocess runner
```
