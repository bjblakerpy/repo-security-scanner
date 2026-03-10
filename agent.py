"""
Security Scan Agent
Runs gitleaks, semgrep, pip-audit/npm audit against a repo,
triages findings via Claude, creates Notion tickets, sends email digest.
"""

import os
import json
import subprocess
import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import anthropic
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config (set via environment variables or edit defaults below)
# ---------------------------------------------------------------------------
REPO_PATH        = os.getenv("REPO_PATH", ".")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
NOTION_TOKEN     = os.getenv("NOTION_TOKEN", "")
NOTION_DATABASE_ID = os.getenv("NOTION_DATABASE_ID", "")   # ID of your Findings DB
SMTP_HOST        = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER        = os.getenv("SMTP_USER", "")
SMTP_PASS        = os.getenv("SMTP_PASS", "")
EMAIL_FROM       = os.getenv("EMAIL_FROM", SMTP_USER)
EMAIL_TO         = os.getenv("EMAIL_TO", "")               # comma-separated list


# ---------------------------------------------------------------------------
# Scanner wrappers
# ---------------------------------------------------------------------------

def run(cmd: list[str], cwd: str = None) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or REPO_PATH)
    return result.returncode, result.stdout, result.stderr


def scan_secrets() -> list[dict]:
    """Run gitleaks against full git history."""
    log.info("Running gitleaks...")
    rc, out, err = run([
        "gitleaks", "detect", "--source", ".",
        "--log-opts=--all", "--report-format", "json",
        "--report-path", "/tmp/gitleaks.json", "--no-banner"
    ])
    try:
        findings = json.loads(Path("/tmp/gitleaks.json").read_text())
        return [{"scanner": "gitleaks", "severity": "CRITICAL", **f} for f in (findings or [])]
    except Exception:
        return []


def scan_sast() -> list[dict]:
    """Run semgrep with auto config."""
    log.info("Running semgrep...")
    rc, out, err = run([
        "semgrep", "--config=auto", "--json", "--quiet", "."
    ])
    try:
        data = json.loads(out)
        results = data.get("results", [])
        return [{"scanner": "semgrep", "severity": r.get("extra", {}).get("severity", "WARNING"), **r} for r in results]
    except Exception:
        return []


def scan_python_deps() -> list[dict]:
    """Run pip-audit if requirements.txt or pyproject.toml exists."""
    repo = Path(REPO_PATH)
    has_py = any([
        (repo / "requirements.txt").exists(),
        (repo / "pyproject.toml").exists(),
        (repo / "Pipfile").exists(),
    ])
    if not has_py:
        return []
    log.info("Running pip-audit...")
    rc, out, err = run(["pip-audit", "--format", "json"])
    try:
        data = json.loads(out)
        vulns = data.get("dependencies", [])
        findings = []
        for dep in vulns:
            for v in dep.get("vulns", []):
                findings.append({
                    "scanner": "pip-audit",
                    "severity": "HIGH",
                    "package": dep["name"],
                    "installed_version": dep["version"],
                    "vuln_id": v["id"],
                    "description": v.get("description", ""),
                    "fix_versions": v.get("fix_versions", []),
                })
        return findings
    except Exception:
        return []


def scan_node_deps() -> list[dict]:
    """Run npm audit if package.json exists."""
    if not (Path(REPO_PATH) / "package.json").exists():
        return []
    log.info("Running npm audit...")
    rc, out, err = run(["npm", "audit", "--json"])
    try:
        data = json.loads(out)
        vulns = data.get("vulnerabilities", {})
        findings = []
        for name, info in vulns.items():
            findings.append({
                "scanner": "npm-audit",
                "severity": info.get("severity", "UNKNOWN").upper(),
                "package": name,
                "description": info.get("title", ""),
                "via": [str(v) for v in info.get("via", [])],
                "fix_available": info.get("fixAvailable", False),
            })
        return findings
    except Exception:
        return []


def run_all_scans() -> list[dict]:
    all_findings = []
    for scanner in [scan_secrets, scan_sast, scan_python_deps, scan_node_deps]:
        try:
            all_findings.extend(scanner())
        except Exception as e:
            log.warning(f"Scanner {scanner.__name__} failed: {e}")
    return all_findings


# ---------------------------------------------------------------------------
# Claude triage
# ---------------------------------------------------------------------------

def triage_with_claude(findings: list[dict]) -> dict:
    """Send findings to Claude, get back structured triage."""
    if not findings:
        return {"summary": "No findings.", "critical": [], "high": [], "medium": [], "low": []}

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""You are a security engineer triaging automated scan results.

Here are the raw findings from multiple scanners (JSON):
{json.dumps(findings, indent=2)[:12000]}  # truncate for context safety

Please return ONLY valid JSON (no markdown) in this exact structure:
{{
  "summary": "2-3 sentence executive summary of overall risk",
  "critical": [
    {{"title": "...", "detail": "...", "recommendation": "...", "scanner": "..."}}
  ],
  "high": [...],
  "medium": [...],
  "low": [...]
}}

Rules:
- Deduplicate similar findings
- Secrets/credentials are always CRITICAL
- Be specific in recommendations (e.g. "rotate API key", "upgrade lodash to 4.17.21")
- Skip noise (test files, dev-only deps with no attack surface)
- Keep each item's detail field under 200 chars
"""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = response.content[0].text.strip().lstrip("```json").rstrip("```").strip()
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Notion integration
# ---------------------------------------------------------------------------

NOTION_HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Content-Type": "application/json",
    "Notion-Version": "2022-06-28",
}


def severity_to_notion_select(severity: str) -> str:
    return severity.upper() if severity.upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "LOW"


def create_notion_page(finding: dict, severity: str) -> str | None:
    """Create a single finding page in the Notion database."""
    payload = {
        "parent": {"database_id": NOTION_DATABASE_ID},
        "properties": {
            "Title": {
                "title": [{"text": {"content": finding.get("title", "Untitled Finding")}}]
            },
            "Severity": {
                "select": {"name": severity_to_notion_select(severity)}
            },
            "Scanner": {
                "rich_text": [{"text": {"content": finding.get("scanner", "unknown")}}]
            },
            "Status": {
                "select": {"name": "Open"}
            },
            "Date Found": {
                "date": {"start": datetime.utcnow().date().isoformat()}
            },
        },
        "children": [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"type": "text", "text": {"content": finding.get("detail", "")}}]
                }
            },
            {
                "object": "block",
                "type": "callout",
                "callout": {
                    "rich_text": [{"type": "text", "text": {"content": f"Recommendation: {finding.get('recommendation', '')}"}}],
                    "icon": {"emoji": "🔧"}
                }
            }
        ]
    }

    resp = requests.post("https://api.notion.com/v1/pages", headers=NOTION_HEADERS, json=payload)
    if resp.status_code == 200:
        return resp.json().get("url")
    else:
        log.warning(f"Notion page creation failed: {resp.status_code} {resp.text[:200]}")
        return None


def push_to_notion(triage: dict) -> dict[str, list[str]]:
    """Create Notion pages for all findings, return map of severity -> page URLs."""
    urls: dict[str, list[str]] = {"critical": [], "high": [], "medium": [], "low": []}
    for severity in ["critical", "high", "medium", "low"]:
        for finding in triage.get(severity, []):
            url = create_notion_page(finding, severity)
            if url:
                urls[severity].append(url)
    return urls


# ---------------------------------------------------------------------------
# Email digest
# ---------------------------------------------------------------------------

def build_email_html(triage: dict, notion_urls: dict) -> str:
    severity_colors = {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#fbc02d",
        "low": "#388e3c",
    }

    counts = {s: len(triage.get(s, [])) for s in ["critical", "high", "medium", "low"]}
    total = sum(counts.values())

    rows = ""
    for severity in ["critical", "high", "medium", "low"]:
        color = severity_colors[severity]
        for i, finding in enumerate(triage.get(severity, [])):
            notion_link = notion_urls.get(severity, [None])[i] if i < len(notion_urls.get(severity, [])) else None
            link_html = f' &nbsp;<a href="{notion_link}" style="font-size:11px;">View in Notion →</a>' if notion_link else ""
            rows += f"""
            <tr>
              <td style="padding:8px;border-bottom:1px solid #eee;">
                <span style="background:{color};color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;">{severity.upper()}</span>
              </td>
              <td style="padding:8px;border-bottom:1px solid #eee;"><strong>{finding['title']}</strong>{link_html}<br>
                <span style="color:#666;font-size:12px;">{finding['detail']}</span></td>
              <td style="padding:8px;border-bottom:1px solid #eee;font-size:12px;color:#333;">{finding['recommendation']}</td>
            </tr>"""

    return f"""
<html><body style="font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px;">
  <h2 style="color:#1a1a2e;">🔐 Security Scan Digest — {datetime.utcnow().strftime('%Y-%m-%d')}</h2>
  <p style="background:#f5f5f5;padding:12px;border-left:4px solid #1a1a2e;">{triage.get('summary','')}</p>

  <table style="border-collapse:collapse;width:100%;margin:8px 0;">
    <tr>
      {''.join(f'<td style="text-align:center;padding:10px;background:{severity_colors[s]};color:white;border-radius:4px;margin:2px;"><strong>{counts[s]}</strong><br><small>{s.upper()}</small></td>' for s in ["critical","high","medium","low"])}
    </tr>
  </table>

  {'<p style="color:green;font-size:16px;">✅ No findings to report.</p>' if total == 0 else f'''
  <table style="width:100%;border-collapse:collapse;margin-top:16px;">
    <thead>
      <tr style="background:#f0f0f0;">
        <th style="padding:8px;text-align:left;width:90px;">Severity</th>
        <th style="padding:8px;text-align:left;">Finding</th>
        <th style="padding:8px;text-align:left;">Recommendation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>'''}

  <p style="color:#999;font-size:11px;margin-top:24px;">Generated by Security Scan Agent · {datetime.utcnow().isoformat()}Z</p>
</body></html>"""


def send_email(triage: dict, notion_urls: dict):
    if not all([SMTP_USER, SMTP_PASS, EMAIL_TO]):
        log.warning("Email not configured, skipping.")
        return

    counts = {s: len(triage.get(s, [])) for s in ["critical", "high", "medium", "low"]}
    subject = (
        f"🚨 Security Scan: {counts['critical']} Critical, {counts['high']} High — {datetime.utcnow().strftime('%Y-%m-%d')}"
        if counts["critical"] or counts["high"]
        else f"✅ Security Scan Clean — {datetime.utcnow().strftime('%Y-%m-%d')}"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    html = build_email_html(triage, notion_urls)
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(EMAIL_FROM, EMAIL_TO.split(","), msg.as_string())
    log.info(f"Email sent to {EMAIL_TO}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_agent():
    log.info(f"Starting security scan on {REPO_PATH}")

    findings = run_all_scans()
    log.info(f"Raw findings: {len(findings)}")

    triage = triage_with_claude(findings)
    log.info(f"Triage complete: {sum(len(triage.get(s,[])) for s in ['critical','high','medium','low'])} triaged findings")

    notion_urls: dict = {}
    if NOTION_TOKEN and NOTION_DATABASE_ID:
        notion_urls = push_to_notion(triage)
        log.info(f"Notion pages created: {sum(len(v) for v in notion_urls.values())}")
    else:
        log.warning("Notion not configured, skipping.")

    send_email(triage, notion_urls)
    log.info("Agent run complete.")
    return triage


if __name__ == "__main__":
    run_agent()
