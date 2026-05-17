"""Generate incident reports for ThreatLens AI."""

from __future__ import annotations

from datetime import datetime, timezone


def build_markdown_report(events: list[dict], findings: list[dict], summary: str) -> str:
    """Return a Markdown incident report."""
    lines = [
        "# ThreatLens AI Incident Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        summary,
        "",
        "## Log Intake",
        "",
        f"- Parsed events: {len(events)}",
        f"- Findings: {len(findings)}",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No findings.")
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.get('summary', 'Finding')}",
                "",
                f"- Severity: `{finding.get('severity', 'unknown')}`",
                f"- Type: `{finding.get('kind', 'unknown')}`",
                f"- Evidence: `{finding.get('evidence', {})}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
