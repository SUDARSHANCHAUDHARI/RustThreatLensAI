# RustThreatLensAI — Claude Code Context

## Purpose
Rust CLI tool that analyzes log files for threats — detects brute-force attacks,
exposed secrets, suspicious IPs, and anomalous patterns in auth/nginx/docker logs.

## Type
Rust CLI (threatlens)

## Stack
- Language: Rust (stable)
- CLI: clap
- Regex: regex
- Serialization: serde + serde_json
- Errors: anyhow + thiserror
- Terminal: colored
- Date/time: chrono

## Commands
```bash
cargo run -- analyze /var/log/auth.log
cargo run -- analyze nginx.log --log-type nginx
cargo run -- analyze auth.log --json
cargo test
cargo clippy
cargo fmt
cargo build --release
```

## Module Structure
```
src/
  main.rs           — entry point, CLI routing
  cli.rs            — clap definitions
  report.rs         — ThreatReport struct
  parser/mod.rs     — parse log lines into LogEvents
  detector/mod.rs   — brute force, secret, IP detection rules
  output/
    terminal.rs     — colored terminal output
    json.rs         — JSON output
tests/
  integration_test.rs
```

## GitHub Repo
https://github.com/SUDARSHANCHAUDHARI/RustThreatLensAI

## Known Issues
None — initial scaffold
