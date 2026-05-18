"""Tests for ThreatLens AI MVP behavior."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apps.api.app.services.log_parser import parse_log_files
from apps.api.app.services.report_generator import build_triage_report, ip_risk_table
from apps.api.app.services.threat_detector import detect_threats


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = [
    ROOT / "data/samples/auth.log",
    ROOT / "data/samples/nginx-access.log",
    ROOT / "data/samples/docker.log",
]


class ThreatLensTests(unittest.TestCase):
    def test_parses_sample_logs(self) -> None:
        events = parse_log_files(SAMPLES)

        self.assertGreaterEqual(len(events), 9)
        self.assertTrue(any(event["event_type"] == "ssh_failed_login" for event in events))
        self.assertTrue(any(event["event_type"] == "http_request" for event in events))

    def test_detects_expected_findings(self) -> None:
        findings = detect_threats(parse_log_files(SAMPLES))
        kinds = {finding["kind"] for finding in findings}

        self.assertIn("auth.bruteforce", kinds)
        self.assertIn("web.suspicious_request", kinds)
        self.assertIn("secret.exposure", kinds)
        self.assertIn("ip.multi_signal", kinds)

    def test_builds_ip_risk_table(self) -> None:
        events = parse_log_files(SAMPLES)
        findings = detect_threats(events)
        rows = ip_risk_table(events, findings)

        self.assertTrue(any(row["ip"] == "198.51.100.22" for row in rows))
        self.assertIn("ThreatLens AI Triage Report", build_triage_report(events, findings))

    def test_cli_writes_findings_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "apps.api.app.cli",
                    "analyze",
                    *[str(sample) for sample in SAMPLES],
                    "--events",
                    str(out / "events.json"),
                    "--findings",
                    str(out / "findings.json"),
                    "--ip-risk",
                    str(out / "ip-risk.json"),
                    "--report",
                    str(out / "report.md"),
                    "--triage-report",
                    str(out / "triage.md"),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            ip_risk = json.loads((out / "ip-risk.json").read_text(encoding="utf-8"))
            report = (out / "report.md").read_text(encoding="utf-8")
            triage = (out / "triage.md").read_text(encoding="utf-8")

            self.assertIn("Parsed", result.stdout)
            self.assertGreaterEqual(len(findings), 4)
            self.assertGreaterEqual(len(ip_risk), 3)
            self.assertIn("ThreatLens AI Incident Report", report)
            self.assertIn("Priority Queue", report)
            self.assertIn("ThreatLens AI Triage Report", triage)


if __name__ == "__main__":
    unittest.main()
