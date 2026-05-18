# Demo Walkthrough

ThreatLens AI ships with safe synthetic logs for a kiosk-like Linux host.

## Scenario

- `auth.log` contains repeated failed SSH logins from `198.51.100.22`.
- `nginx-access.log` contains requests for `/.env`, `/wp-admin`, and a SQL injection-looking search path.
- `docker.log` contains container activity and a synthetic bearer-token exposure.

## Run

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

Expected output:

```text
Parsed 11 events
Wrote 7 findings to data/reports/findings.json
Wrote report to data/reports/incident-report.md
Wrote triage report to data/reports/triage-report.md
```

## Inspect

- `data/reports/incident-report.md`
- `data/reports/triage-report.md`
- `data/reports/ip-risk.json`
- `data/reports/findings.json`
