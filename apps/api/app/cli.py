"""Command line interface for the ThreatLens AI MVP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apps.api.app.services.ai_summary import summarize_findings
from apps.api.app.services.log_parser import parse_log_files
from apps.api.app.services.report_generator import build_markdown_report, build_triage_report, ip_risk_table
from apps.api.app.services.threat_detector import detect_threats


def write_json(path: Path, payload: list[dict] | dict) -> None:
    """Write formatted JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def analyze_command(args: argparse.Namespace) -> None:
    """Analyze log files and write findings/report artifacts."""
    events = parse_log_files(args.logs)
    findings = detect_threats(events)
    summary = summarize_findings(findings, args.summary_provider)

    write_json(args.events, events)
    write_json(args.findings, findings)
    write_json(args.ip_risk, ip_risk_table(events, findings))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(build_markdown_report(events, findings, summary), encoding="utf-8")
    args.triage_report.parent.mkdir(parents=True, exist_ok=True)
    args.triage_report.write_text(build_triage_report(events, findings), encoding="utf-8")

    print(f"Parsed {len(events)} events")
    print(f"Wrote {len(findings)} findings to {args.findings}")
    print(f"Wrote report to {args.report}")
    print(f"Wrote triage report to {args.triage_report}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ThreatLens AI MVP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze auth, nginx, and Docker logs")
    analyze.add_argument("logs", nargs="+", type=Path)
    analyze.add_argument("--events", type=Path, default=Path("data/reports/events.json"))
    analyze.add_argument("--findings", type=Path, default=Path("data/reports/findings.json"))
    analyze.add_argument("--ip-risk", type=Path, default=Path("data/reports/ip-risk.json"))
    analyze.add_argument("--report", type=Path, default=Path("data/reports/incident-report.md"))
    analyze.add_argument("--triage-report", type=Path, default=Path("data/reports/triage-report.md"))
    analyze.add_argument("--summary-provider", default="deterministic", choices=["deterministic", "external-ai-placeholder"])
    analyze.set_defaults(func=analyze_command)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
