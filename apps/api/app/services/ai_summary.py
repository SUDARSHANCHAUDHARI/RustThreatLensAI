"""Generate incident summaries through pluggable summary providers."""

from __future__ import annotations

from collections import Counter, defaultdict


def _severity_counts(findings: list[dict]) -> Counter:
    return Counter(str(finding.get("severity", "unknown")) for finding in findings)


def _top_ips(findings: list[dict]) -> list[str]:
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        evidence = finding.get("evidence", {})
        ip = evidence.get("ip")
        if ip:
            counts[str(ip)] += 1
    return [ip for ip, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:3]]


class DeterministicSummaryProvider:
    """Offline provider used for tests, demos, and safe portfolio output."""

    name = "deterministic"

    def summarize(self, findings: list[dict]) -> str:
        if not findings:
            return "No suspicious events were detected in the provided logs."

        counts = _severity_counts(findings)
        kinds = sorted({str(finding.get("kind")) for finding in findings})
        top_ips = _top_ips(findings)
        lead = (
            f"ThreatLens identified {len(findings)} finding(s): "
            f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
            f"{counts.get('medium', 0)} medium."
        )
        themes = " Key themes: " + ", ".join(kinds) + "."
        ip_note = f" Priority IPs: {', '.join(top_ips)}." if top_ips else ""
        recommendation = (
            " Review critical items first, block abusive source IPs where appropriate, "
            "rotate exposed credentials, and preserve original logs for incident review."
        )
        return lead + themes + ip_note + recommendation


class AISummaryProvider:
    """Placeholder boundary for a future OpenAI/Claude-backed provider."""

    name = "external-ai-placeholder"

    def summarize(self, findings: list[dict]) -> str:
        return DeterministicSummaryProvider().summarize(findings)


def get_summary_provider(name: str = "deterministic"):
    """Return a summary provider by name."""
    if name == "external-ai-placeholder":
        return AISummaryProvider()
    return DeterministicSummaryProvider()


def summarize_findings(findings: list[dict], provider_name: str = "deterministic") -> str:
    """Return a concise analyst-style summary."""
    return get_summary_provider(provider_name).summarize(findings)
