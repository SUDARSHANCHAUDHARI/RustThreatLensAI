# ThreatLens AI

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

AI-powered log investigation assistant for auth, nginx, Docker logs, suspicious IPs, secrets, and incident reports.

- **Portfolio group:** Product-style SaaS project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/ThreatLensAI
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/ThreatLensAI`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

## Core Features

- log upload
- auth/nginx/docker parser
- suspicious IP detection
- brute-force detection
- exposed secret detection
- AI summary
- incident report export

## Suggested Stack

FastAPI, React, PostgreSQL, OpenAI/Claude, Docker.

## Status

Working CLI MVP.

## Quick Start

Analyze the included safe sample logs:

```bash
python3 -m apps.api.app.cli analyze \
  data/samples/auth.log \
  data/samples/nginx-access.log \
  data/samples/docker.log \
  --events data/reports/events.json \
  --findings data/reports/findings.json \
  --ip-risk data/reports/ip-risk.json \
  --report data/reports/incident-report.md \
  --triage-report data/reports/triage-report.md
```

Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## MVP Capabilities

- Parses Linux auth logs, nginx access logs, and Docker daemon/app logs.
- Detects repeated SSH failed-login brute-force behavior.
- Flags suspicious web paths and scanner user agents.
- Detects credential-like material in logs.
- Correlates IPs across multiple event types.
- Builds a deterministic summary through a provider boundary.
- Generates JSON events, findings, IP risk tables, an incident report, and a triage report.

## Demo Artifacts

- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Demo walkthrough](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Sample incident report](data/reports/incident-report.md)
- [Sample triage report](data/reports/triage-report.md)

## Docker Demo

```bash
docker compose run --rm threatlens-demo
```

## Roadmap

- Add redaction pipeline before external AI providers
- Add parser confidence and parse-error reporting
- Add more log fixtures for MFA, container privilege drift, and web bursts
- Add FastAPI upload endpoint and React dashboard
- Prepare GitHub release `v0.1.0-mvp`
