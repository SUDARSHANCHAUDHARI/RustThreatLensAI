"""Generate incident reports for ThreatLens AI."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
NEXT_STEPS = {
    "secret.exposure": "Rotate the exposed credential, redact affected logs, and review downstream access.",
    "auth.bruteforce": "Block or rate-limit the source IP and verify no successful login followed the failures.",
    "web.suspicious_request": "Review the request path, user agent, and response code; add WAF or app rules if needed.",
    "ip.multi_signal": "Correlate this IP across auth, web, and infrastructure logs before closing the incident.",
}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "")), 0), reverse=True)


def severity_counts(findings: list[dict]) -> Counter:
    return Counter(str(finding.get("severity", "unknown")) for finding in findings)


def ip_risk_table(events: list[dict], findings: list[dict]) -> list[dict]:
    """Build a compact IP-centric risk table."""
    event_types: dict[str, set[str]] = defaultdict(set)
    finding_counts: dict[str, int] = defaultdict(int)
    max_severity: dict[str, str] = {}
    for event in events:
        if event.get("ip"):
            event_types[str(event["ip"])].add(str(event.get("event_type", "unknown")))
    for finding in findings:
        evidence = finding.get("evidence", {})
        ip = evidence.get("ip")
        if not ip:
            continue
        ip = str(ip)
        finding_counts[ip] += 1
        severity = str(finding.get("severity", "low"))
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity.get(ip, "low"), 0):
            max_severity[ip] = severity
    rows = []
    for ip in sorted(set(event_types) | set(finding_counts)):
        rows.append(
            {
                "ip": ip,
                "event_types": sorted(event_types.get(ip, set())),
                "finding_count": finding_counts.get(ip, 0),
                "max_severity": max_severity.get(ip, "low"),
            }
        )
    return sorted(rows, key=lambda row: (-SEVERITY_ORDER.get(row["max_severity"], 0), -row["finding_count"], row["ip"]))


def _format_evidence(evidence: dict) -> str:
    return ", ".join(f"{key}={value}" for key, value in evidence.items()) or "no evidence"


def build_markdown_report(events: list[dict], findings: list[dict], summary: str) -> str:
    """Return a Markdown incident report."""
    sorted_findings = sort_findings(findings)
    counts = severity_counts(sorted_findings)
    rows = ip_risk_table(events, sorted_findings)
    lines = [
        "# ThreatLens AI Incident Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        "## Log Intake",
        "",
        f"- Parsed events: {len(events)}",
        f"- Findings: {len(sorted_findings)}",
        f"- Critical: {counts.get('critical', 0)}",
        f"- High: {counts.get('high', 0)}",
        f"- Medium: {counts.get('medium', 0)}",
        "",
        "## Priority Queue",
        "",
    ]

    if not sorted_findings:
        lines.append("No immediate investigation queue was generated.")
    for index, finding in enumerate(sorted_findings[:3], start=1):
        lines.append(f"{index}. **{finding.get('severity')}** - {finding.get('summary')} ({finding.get('kind')})")

    lines.extend(["", "## IP Risk Table", ""])
    if not rows:
        lines.append("No IP-linked activity was parsed.")
    else:
        lines.extend(["| IP | Max Severity | Findings | Event Types |", "| --- | --- | ---: | --- |"])
        for row in rows:
            lines.append(
                f"| {row['ip']} | {row['max_severity']} | {row['finding_count']} | {', '.join(row['event_types'])} |"
            )

    lines.extend(["", "## Findings", ""])
    if not sorted_findings:
        lines.append("No findings.")
    for index, finding in enumerate(sorted_findings, start=1):
        kind = str(finding.get("kind", "unknown"))
        lines.extend(
            [
                f"### {index}. {finding.get('summary', 'Finding')}",
                "",
                f"- Severity: `{finding.get('severity', 'unknown')}`",
                f"- Type: `{kind}`",
                f"- Evidence: `{_format_evidence(finding.get('evidence', {}))}`",
                f"- Recommended next step: {NEXT_STEPS.get(kind, 'Review this finding with the original log context.')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def build_triage_report(events: list[dict], findings: list[dict]) -> str:
    """Return a compact triage report for dashboards or handoff."""
    rows = ip_risk_table(events, findings)
    lines = [
        "# ThreatLens AI Triage Report",
        "",
        f"- Parsed events: {len(events)}",
        f"- Active findings: {len(findings)}",
        "",
        "## Highest Risk IPs",
        "",
    ]
    for row in rows[:5]:
        lines.append(f"- `{row['ip']}`: {row['max_severity']}, {row['finding_count']} finding(s), {', '.join(row['event_types'])}")
    lines.extend(["", "## Analyst Notes", ""])
    if findings:
        lines.extend(
            [
                "- Start with credential exposure before IP blocking.",
                "- Preserve original logs before redaction.",
                "- Check whether brute-force IPs also reached web endpoints.",
            ]
        )
    else:
        lines.append("- No suspicious activity detected in the parsed sample.")
    return "\n".join(lines).rstrip() + "\n"
