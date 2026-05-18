# RustThreatLensAI

Rust CLI that analyzes log files for security threats. Detects brute-force attacks, exposed secrets, and suspicious IPs in auth, nginx, and docker logs.

## Install

```bash
cargo build --release
# binary at target/release/threatlens
```

## Usage

```bash
# Analyze a log file (auto-detect type)
threatlens analyze /var/log/auth.log

# Specify log type
threatlens analyze nginx.log --log-type nginx

# JSON output
threatlens analyze auth.log --json
```

## Log types

| Type | Detects |
|---|---|
| `auth` | Failed/successful SSH logins, usernames, IPs |
| `nginx` | HTTP methods, request IPs |
| `docker` | Container events |
| `auto` | Auto-detects from line content |

## Detection rules

| Rule | Severity | Trigger |
|---|---|---|
| `BRUTE_FORCE` | Critical | 5+ failed logins from same IP |
| `SECRET_IN_LOGS` | High | Lines containing `password=`, `token=`, `Authorization: Bearer`, etc. |
| `SUSPICIOUS_IP` | Medium | Known suspicious IP ranges |

## Risk levels

`Low` → `Medium` → `High` → `Critical`

Based on the highest severity finding detected.

## Test

```bash
cargo test
```

12 integration tests — parser, brute force, secrets, risk scoring, CLI.

## Stack

Rust · clap · regex · serde · colored · anyhow
