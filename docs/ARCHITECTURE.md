# Architecture

RustThreatLensAI is a CLI log threat analyzer for finding brute-force attempts, suspicious IPs, secret-like strings, and risk signals in logs.

## Goals

- Provide a quick local security review of log files.
- Keep parser and detector logic separate.
- Produce terminal and JSON output.
- Avoid uploading logs or storing sensitive data.

## Module Layout

| Module | Responsibility |
| --- | --- |
| `src/cli.rs` | CLI command and output options |
| `src/parser/` | Log type detection and parsing |
| `src/detector/` | Threat and secret-pattern detection |
| `src/report.rs` | Findings and risk summary model |
| `src/output/` | Terminal and JSON rendering |

## Data Flow

1. The CLI receives a log file path and output mode.
2. The parser detects log style and extracts useful fields.
3. The detector evaluates brute-force, suspicious IP, and secret-like patterns.
4. The report computes risk level and findings.
5. The renderer prints terminal or JSON output.

## Design Notes

- Treat logs as sensitive local files.
- Detection rules should explain why a finding exists.
- Secret detection should favor useful warnings without claiming perfect coverage.
- Fixtures must use fake data only.

## Release Assumptions

- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo package` pass before release.
- GitHub Actions are intentionally not used in this repo.
