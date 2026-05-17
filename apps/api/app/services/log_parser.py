"""Parse common security logs into normalized events."""

from __future__ import annotations

import re
from pathlib import Path


AUTH_FAILED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Failed password for(?: invalid user)? "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
AUTH_ACCEPTED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)
NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d+) (?P<size>\S+) "
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def parse_auth_log(text: str) -> list[dict]:
    """Parse Linux auth log lines."""
    events: list[dict] = []
    for line in text.splitlines():
        failed = AUTH_FAILED_RE.search(line)
        if failed:
            events.append(
                {
                    "source": "auth",
                    "event_type": "ssh_failed_login",
                    "timestamp": failed.group("timestamp"),
                    "ip": failed.group("ip"),
                    "user": failed.group("user"),
                    "raw": line,
                }
            )
            continue

        accepted = AUTH_ACCEPTED_RE.search(line)
        if accepted:
            events.append(
                {
                    "source": "auth",
                    "event_type": "ssh_successful_login",
                    "timestamp": accepted.group("timestamp"),
                    "ip": accepted.group("ip"),
                    "user": accepted.group("user"),
                    "raw": line,
                }
            )
    return events


def parse_nginx_log(text: str) -> list[dict]:
    """Parse nginx combined access log lines."""
    events: list[dict] = []
    for line in text.splitlines():
        match = NGINX_RE.match(line)
        if not match:
            continue
        events.append(
            {
                "source": "nginx",
                "event_type": "http_request",
                "timestamp": match.group("timestamp"),
                "ip": match.group("ip"),
                "method": match.group("method"),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "user_agent": match.group("user_agent"),
                "raw": line,
            }
        )
    return events


def parse_docker_log(text: str) -> list[dict]:
    """Parse simple Docker daemon log lines."""
    events: list[dict] = []
    for line in text.splitlines():
        lowered = line.lower()
        if (
            "started container" in lowered
            or "exec" in lowered
            or "error" in lowered
            or "authorization:" in lowered
            or "bearer " in lowered
        ):
            events.append(
                {
                    "source": "docker",
                    "event_type": "docker_activity",
                    "timestamp": line.split(" ", 1)[0],
                    "raw": line,
                }
            )
    return events


def parse_log_file(path: Path) -> list[dict]:
    """Parse a log file based on its filename."""
    text = path.read_text(encoding="utf-8", errors="replace")
    name = path.name.lower()
    if "auth" in name:
        return parse_auth_log(text)
    if "nginx" in name or "access" in name:
        return parse_nginx_log(text)
    if "docker" in name:
        return parse_docker_log(text)
    return []


def parse_log_files(paths: list[Path]) -> list[dict]:
    """Parse multiple log files."""
    events: list[dict] = []
    for path in paths:
        events.extend(parse_log_file(path))
    return events
