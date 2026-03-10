"""Claude-powered triage — deduplicates, prioritizes, and recommends actions."""

from __future__ import annotations

import json
import logging

import anthropic

from secaudit.config import TriageConfig
from secaudit.models import Finding, Severity, TriageResult
from secaudit.utils.retry import retry

log = logging.getLogger(__name__)

TRIAGE_PROMPT = """You are a security engineer triaging automated scan results.

Here are the raw findings from multiple scanners (JSON):
{findings_json}

Please return ONLY valid JSON (no markdown fences) in this exact structure:
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
- Deduplicate similar findings (same vuln across files, same CVE)
- Secrets/credentials are always CRITICAL
- Be specific in recommendations (e.g. "rotate API key", "upgrade lodash to 4.17.21")
- Skip noise (test files, dev-only deps with no attack surface)
- Keep each item's detail field under 200 chars
"""


@retry(max_attempts=3, base_delay=2.0, exceptions=(anthropic.APIError,))
def _call_claude(client: anthropic.Anthropic, model: str, prompt: str) -> str:
    """Call Claude API with retry on transient errors."""
    response = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def triage_findings(findings: list[Finding], config: TriageConfig) -> TriageResult:
    """Send findings to Claude for intelligent triage.

    Args:
        findings: Raw findings from all scanners.
        config: Triage configuration.

    Returns:
        TriageResult with deduplicated, prioritized findings.
    """
    if not findings:
        return TriageResult(
            summary="No findings detected.",
            findings={},
            raw_count=0,
            triaged_count=0,
        )

    if not config.api_key:
        log.warning("No ANTHROPIC_API_KEY configured — returning raw findings without triage")
        return _passthrough_triage(findings)

    # Truncate findings to max_findings
    findings_to_send = findings[: config.max_findings]
    findings_dicts = [f.to_dict() for f in findings_to_send]
    findings_json = json.dumps(findings_dicts, indent=2)

    # Truncate JSON to ~12k chars for context safety
    if len(findings_json) > 12000:
        findings_json = findings_json[:12000] + "\n... (truncated)"

    prompt = TRIAGE_PROMPT.format(findings_json=findings_json)

    client = anthropic.Anthropic(api_key=config.api_key)
    raw_response = _call_claude(client, config.model, prompt)

    # Strip markdown code fences if present
    text = raw_response.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.error("Failed to parse Claude response as JSON")
        return _passthrough_triage(findings)

    # Convert to TriageResult with Finding objects
    triaged: dict[str, list[Finding]] = {}
    triaged_count = 0
    for severity_key in ("critical", "high", "medium", "low"):
        severity = Severity(severity_key.upper())
        items = data.get(severity_key, [])
        triaged_findings = []
        for item in items:
            f = Finding(
                scanner=item.get("scanner", "unknown"),
                severity=severity,
                title=item.get("title", ""),
                description=item.get("detail", ""),
                recommendation=item.get("recommendation", ""),
            )
            f.compute_fingerprint()
            triaged_findings.append(f)
        triaged[severity.value] = triaged_findings
        triaged_count += len(triaged_findings)

    return TriageResult(
        summary=data.get("summary", ""),
        findings=triaged,
        raw_count=len(findings),
        triaged_count=triaged_count,
    )


def _passthrough_triage(findings: list[Finding]) -> TriageResult:
    """Bypass triage — group findings by severity without Claude."""
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        key = f.severity.value
        grouped.setdefault(key, []).append(f)

    return TriageResult(
        summary=f"{len(findings)} raw findings (triage skipped)",
        findings=grouped,
        raw_count=len(findings),
        triaged_count=len(findings),
    )
