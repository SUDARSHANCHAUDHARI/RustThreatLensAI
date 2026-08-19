# RustThreatLensAI

[![crates.io](https://img.shields.io/crates/v/threatlensai?logo=rust)](https://crates.io/crates/threatlensai)
[![Downloads](https://img.shields.io/crates/d/threatlensai?logo=rust)](https://crates.io/crates/threatlensai)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)

> A Rust CLI security log analyzer — fast, local, first-pass threat triage from raw logs.

**RustThreatLensAI** (installed as the `threatlensai` command) parses auth, nginx, and
docker-style logs, detects suspicious patterns such as brute-force login attempts and
leaked secrets, and returns a risk report in terminal or JSON format.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Included Example](#included-example)
- [Supported Log Types](#supported-log-types)
- [Detection Rules](#detection-rules)
- [Risk Levels](#risk-levels)
- [Operational Notes](#operational-notes)
- [Development](#development)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Release Status](#release-status)
- [License](#license)
- [About](#about)

## Overview

Small teams often need a fast first-pass threat scan before reaching for a full SIEM.
RustThreatLensAI gives you a local, scriptable tool that can inspect raw logs and surface
high-signal findings with predictable rules.

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

### From crates.io (recommended)

```bash
cargo install threatlensai
```

### From source

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/RustThreatLensAI.git
cd RustThreatLensAI
cargo build --release
```

The binary is created at:

```bash
target/release/threatlensai
```

Optional local install from a source checkout:

```bash
cargo install --path .
```

## Usage

```bash
# Analyze a log file and auto-detect log type
threatlensai analyze /var/log/auth.log

# Specify the log type
threatlensai analyze nginx.log --log-type nginx
threatlensai analyze auth.log --log-type auth
threatlensai analyze docker.log --log-type docker

# Emit JSON
threatlensai analyze auth.log --json

# Raise the brute-force threshold for noisier environments
threatlensai analyze auth.log --brute-force-threshold 10
```

## Included Example

The repository includes a small auth log fixture:

```bash
threatlensai analyze examples/auth.sample

threatlensai analyze examples/auth.sample --brute-force-threshold 6
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

RustThreatLensAI is a local static analyzer. It does not replace centralized logging,
endpoint detection, or incident response tooling. It is best used as a quick triage tool,
CI/security check, or first-pass scan before deeper investigation.

## Development

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

The integration tests cover parser behavior, brute-force detection, configurable thresholds,
secret detection, risk scoring, and CLI output.

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

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Maintainer notes](docs/NOTES.md)
- [Content plan](docs/CONTENT_PLAN.md)

## Release Status

Current release: **`v1.1.1`**, published on [crates.io](https://crates.io/crates/threatlensai).

Each release is verified with formatting, Clippy, tests, an optimized release build, and
`cargo package` before publishing.

## License

MIT — see [LICENSE](LICENSE).

---

## About

I'm Sudarshan Chaudhari, a Senior Quality Engineer, Test Automation specialist, and AI systems builder based in Bangkok, Thailand.

I have 13+ years of experience in software quality engineering, working across SaaS, fintech, gaming, web, mobile, cloud, and digital signage platforms. My background combines hands-on test automation with QA leadership, test strategy, CI/CD, release quality, production investigation, and cross-platform validation.

Alongside my professional QA career, I run [SudarshanTechLabs](https://sudarshantechlabs.com/), my independent engineering and product lab where I design, build, test, and ship software across Android, web, AI, cybersecurity, developer tooling, and cross-platform applications.

### What I work on

- ⚙️ **Quality Engineering & Test Automation** — Playwright, Selenium, Cypress, Appium, API testing, automation frameworks, end-to-end testing, CI/CD, release gates, GitHub Actions, risk-based testing, and production validation
- 🤖 **AI Systems & Automation** — AI agents, multi-agent orchestration, MCP servers, AI-assisted QA, prompt tooling, developer workflows, automation systems, and Claude Code plugins
- 📱 **Mobile & Cross-Platform Applications** — Android applications built with Kotlin and Jetpack Compose, Google Play releases, automated build and publishing pipelines, and cross-platform development spanning iOS, web, Windows, and macOS
- 🌐 **Web Applications & Platforms** — Full-stack applications using Next.js, TypeScript, Firebase, Cloudflare, REST APIs, and modern web infrastructure
- 🛠️ **Developer Tooling & CLI Engineering** — Rust, Python, TypeScript, CLI utilities, multi-repository tooling, build automation, release tooling, and engineering productivity systems
- 🛡️ **Cybersecurity & Observability** — Threat detection, log analysis, security auditing, vulnerability assessment, monitoring, and security-focused developer tools
- 📺 **Digital Signage & Device Platforms** — Content validation, playback testing, device compatibility, production investigation, monitoring, and QA across diverse hardware and operating-system environments

My work sits at the intersection of quality engineering, automation, AI, and software development. I approach products with a QA mindset from the beginning: understanding failure modes, designing for testability, automating repetitive work, and building release confidence into the engineering process.

Through SudarshanTechLabs, I also build products and tools from idea to production, covering architecture, development, testing, CI/CD, release automation, monitoring, and ongoing maintenance.

🌐 [sudarshantechlabs.com](https://sudarshantechlabs.com/) · 💼 [LinkedIn](https://linkedin.com/in/sudarshan-chaudhari) · 🐙 [GitHub](https://github.com/SUDARSHANCHAUDHARI) · ✉️ [sunny.sudarshan@gmail.com](mailto:sunny.sudarshan@gmail.com)
