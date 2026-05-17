"""Detect suspicious behavior from normalized log events."""

from __future__ import annotations

import re
from collections import Counter, defaultdict


SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{12,}", re.IGNORECASE),
)
SUSPICIOUS_PATH_MARKERS = (
    "/wp-admin",
    "/.env",
    "/admin",
    "select%20",
    "union%20select",
    "<script",
    "../",
)
SUSPICIOUS_USER_AGENTS = ("sqlmap", "nikto", "masscan", "nmap")


def _finding(kind: str, severity: str, summary: str, evidence: dict) -> dict:
    return {
        "kind": kind,
        "severity": severity,
        "summary": summary,
        "evidence": evidence,
    }


def detect_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    """Detect repeated SSH login failures by IP."""
    counts = Counter(event["ip"] for event in events if event.get("event_type") == "ssh_failed_login")
    findings: list[dict] = []
    for ip, count in counts.items():
        if count >= threshold:
            users = sorted(
                {
                    str(event.get("user", "unknown"))
                    for event in events
                    if event.get("event_type") == "ssh_failed_login" and event.get("ip") == ip
                }
            )
            findings.append(
                _finding(
                    "auth.bruteforce",
                    "high",
                    "Repeated SSH login failures indicate a brute-force attempt.",
                    {"ip": ip, "failed_attempts": count, "users": users},
                )
            )
    return findings


def detect_suspicious_http(events: list[dict]) -> list[dict]:
    """Detect suspicious web request paths and user agents."""
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for event in events:
        if event.get("event_type") != "http_request":
            continue
        path = str(event.get("path", "")).lower()
        user_agent = str(event.get("user_agent", "")).lower()
        matched_path = next((marker for marker in SUSPICIOUS_PATH_MARKERS if marker in path), "")
        matched_agent = next((marker for marker in SUSPICIOUS_USER_AGENTS if marker in user_agent), "")
        if not matched_path and not matched_agent:
            continue
        key = (str(event.get("ip", "")), path, matched_agent or matched_path)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            _finding(
                "web.suspicious_request",
                "medium",
                "HTTP request matches a suspicious path or scanner signature.",
                {
                    "ip": event.get("ip"),
                    "path": event.get("path"),
                    "status": event.get("status"),
                    "user_agent": event.get("user_agent"),
                    "matched": matched_agent or matched_path,
                },
            )
        )
    return findings


def detect_secret_exposure(events: list[dict]) -> list[dict]:
    """Detect exposed credential-like material in raw logs."""
    findings: list[dict] = []
    for event in events:
        raw = str(event.get("raw", ""))
        for pattern in SECRET_PATTERNS:
            if pattern.search(raw):
                findings.append(
                    _finding(
                        "secret.exposure",
                        "critical",
                        "Log line contains credential-like material and should be redacted.",
                        {
                            "source": event.get("source"),
                            "event_type": event.get("event_type"),
                            "raw_preview": raw[:120],
                        },
                    )
                )
                break
    return findings


def detect_ip_risk(events: list[dict]) -> list[dict]:
    """Flag IPs seen across several suspicious event types."""
    types_by_ip: dict[str, set[str]] = defaultdict(set)
    for event in events:
        ip = event.get("ip")
        if ip:
            types_by_ip[str(ip)].add(str(event.get("event_type", "unknown")))

    findings: list[dict] = []
    for ip, event_types in sorted(types_by_ip.items()):
        if len(event_types) >= 2:
            findings.append(
                _finding(
                    "ip.multi_signal",
                    "medium",
                    "IP appears across multiple event types and deserves review.",
                    {"ip": ip, "event_types": sorted(event_types)},
                )
            )
    return findings


def detect_threats(events: list[dict]) -> list[dict]:
    """Run all MVP detectors."""
    findings = [
        *detect_bruteforce(events),
        *detect_suspicious_http(events),
        *detect_secret_exposure(events),
        *detect_ip_risk(events),
    ]
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return sorted(findings, key=lambda item: severity_order.get(item["severity"], 0), reverse=True)
