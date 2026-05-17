# ThreatLens AI

**Goal:** AI-powered log investigation assistant.

**MVP:** Upload logs, detect suspicious events, and explain findings.

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
  --report data/reports/incident-report.md
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
- Generates JSON events, JSON findings, and a Markdown incident report.

## Repository Status

This repository contains the production-ready foundation for the ThreatLens AI MVP. The current codebase is scaffolded and ready for focused implementation work.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
