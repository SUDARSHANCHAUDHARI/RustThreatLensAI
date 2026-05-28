# RustThreatLensAI

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)

RustThreatLensAI is a Rust CLI security log analyzer. It parses auth, nginx, and docker-style logs, detects suspicious patterns such as brute-force login attempts and leaked secrets, and returns a risk report in terminal or JSON format.

## Why This Exists

Small teams often need a fast first-pass threat scan before reaching for a full SIEM. RustThreatLensAI gives you a local, scriptable tool that can inspect raw logs and surface high-signal findings with predictable rules.

## Features

- Parses auth, nginx, docker, or auto-detected log input.
- Detects failed and successful SSH login events.
- Detects HTTP request method and IP patterns in nginx-style logs.
- Detects docker/container event lines.
- Flags brute-force behavior when an IP has 5 or more failed logins.
- Flags likely secrets in logs, including password, token, API key, secret, and bearer-style patterns.
- Flags suspicious IP ranges from built-in rules.
- Produces `Low`, `Medium`, `High`, or `Critical` risk levels.
- Supports terminal output and JSON output.

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/RustThreatLensAI.git
cd RustThreatLensAI
cargo build --release
```

The binary is created at:

```bash
target/release/threatlens
```

Optional local install:

```bash
cargo install --path .
```

## Usage

```bash
# Analyze a log file and auto-detect log type
threatlens analyze /var/log/auth.log

# Specify the log type
threatlens analyze nginx.log --log-type nginx
threatlens analyze auth.log --log-type auth
threatlens analyze docker.log --log-type docker

# Emit JSON
threatlens analyze auth.log --json

# Raise the brute-force threshold for noisier environments
threatlens analyze auth.log --brute-force-threshold 10
```

## Included Example

The repository includes a small auth log fixture:

```bash
threatlens analyze examples/auth.sample

threatlens analyze examples/auth.sample --brute-force-threshold 6
```

Real output:

```text
ThreatLens Report
File: examples/auth.sample
Log Type: auto
Total Events: 7
Risk: Critical
Summary: 2 threat(s) detected. Immediate review recommended.

Findings:
  BRUTE_FORCE — 1 IP(s) with 5+ failed login attempts detected
    10.0.0.1: 5 failed attempts
  SECRET_IN_LOGS — 1 line(s) may contain exposed secrets
    2026-05-18 curl -H 'Authorization: Bearer example-token-value' https://api.example.com
```

## Supported Log Types

| Type | Detection Focus |
|---|---|
| `auth` | SSH login success/failure, usernames, source IPs |
| `nginx` | HTTP methods, request IPs, web access patterns |
| `docker` | Container and runtime event lines |
| `auto` | Best-effort detection from line content |

## Detection Rules

| Rule | Severity | Trigger |
|---|---|---|
| `BRUTE_FORCE` | Critical | Failed login events from the same IP at or above `--brute-force-threshold` |
| `SECRET_IN_LOGS` | High | Secret-like strings such as `password=`, `token=`, `api_key=`, `secret=`, or bearer tokens |
| `SUSPICIOUS_IP` | Medium | Known suspicious IP ranges |

The default brute-force threshold is `5`. Increase it for noisy environments or lower it for stricter local checks.

## Risk Levels

Risk is based on the highest severity finding in the report.

| Risk | Meaning |
|---|---|
| `Low` | No meaningful findings detected |
| `Medium` | Suspicious activity worth reviewing |
| `High` | Sensitive data or serious issue detected |
| `Critical` | Immediate action likely required |

## Operational Notes

RustThreatLensAI is a local static analyzer. It does not replace centralized logging, endpoint detection, or incident response tooling. It is best used as a quick triage tool, CI/security check, or first-pass scan before deeper investigation.

## Development

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

The integration tests cover parser behavior, brute-force detection, configurable thresholds, secret detection, risk scoring, and CLI output.

## Project Structure

```text
src/
  cli.rs          Command-line interface
  parser/         Log parsing and event extraction
  detector/       Threat rules and findings
  report.rs       Risk report output
tests/
  integration_test.rs
```

## Project Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Maintainer notes](docs/NOTES.md)
- [Content plan](docs/CONTENT_PLAN.md)

## Release Status

Current production release: `v1.0.0`

The `v1.0.0` release was verified with formatting, clippy, tests, optimized release build, and `cargo package`.

## License

MIT. See [LICENSE](LICENSE).

## Developer

Built by [Sudarshan Chaudhari](https://github.com/SUDARSHANCHAUDHARI) under SudarshanTechLabs.
