"""Generate deterministic plain-English incident summaries."""

from __future__ import annotations


def summarize_findings(findings: list[dict]) -> str:
    """Return a concise analyst-style summary without external AI calls."""
    if not findings:
        return "No suspicious events were detected in the provided logs."

    critical = sum(1 for finding in findings if finding.get("severity") == "critical")
    high = sum(1 for finding in findings if finding.get("severity") == "high")
    kinds = sorted({str(finding.get("kind")) for finding in findings})

    lead = f"ThreatLens identified {len(findings)} finding(s)"
    if critical or high:
        lead += f", including {critical} critical and {high} high severity item(s)"
    lead += "."

    details = " Key themes: " + ", ".join(kinds) + "."
    recommendation = (
        " Review critical items first, block abusive source IPs where appropriate, rotate exposed credentials, "
        "and preserve the original logs for incident review."
    )
    return lead + details + recommendation
