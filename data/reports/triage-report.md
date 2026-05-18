# ThreatLens AI Triage Report

- Parsed events: 11
- Active findings: 7

## Highest Risk IPs

- `198.51.100.22`: high, 4 finding(s), http_request, ssh_failed_login
- `192.0.2.45`: medium, 1 finding(s), http_request
- `203.0.113.10`: medium, 1 finding(s), http_request, ssh_successful_login

## Analyst Notes

- Start with credential exposure before IP blocking.
- Preserve original logs before redaction.
- Check whether brute-force IPs also reached web endpoints.
