# ThreatLens AI Incident Report

Generated: 2026-05-17T13:48:38.531323+00:00

## Summary

ThreatLens identified 7 finding(s), including 1 critical and 1 high severity item(s). Key themes: auth.bruteforce, ip.multi_signal, secret.exposure, web.suspicious_request. Review critical items first, block abusive source IPs where appropriate, rotate exposed credentials, and preserve the original logs for incident review.

## Log Intake

- Parsed events: 11
- Findings: 7

## Findings

### 1. Log line contains credential-like material and should be redacted.

- Severity: `critical`
- Type: `secret.exposure`
- Evidence: `{'source': 'docker', 'event_type': 'docker_activity', 'raw_preview': '2026-05-17T10:10:45Z app: outbound request header Authorization: Bearer demo-token-value-12345'}`

### 2. Repeated SSH login failures indicate a brute-force attempt.

- Severity: `high`
- Type: `auth.bruteforce`
- Evidence: `{'ip': '198.51.100.22', 'failed_attempts': 3, 'users': ['admin', 'deploy', 'root']}`

### 3. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `{'ip': '198.51.100.22', 'path': '/.env', 'status': 404, 'user_agent': 'sqlmap/1.7', 'matched': 'sqlmap'}`

### 4. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `{'ip': '198.51.100.22', 'path': '/wp-admin', 'status': 404, 'user_agent': 'Mozilla/5.0', 'matched': '/wp-admin'}`

### 5. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `{'ip': '192.0.2.45', 'path': '/search?q=union%20select%20password', 'status': 403, 'user_agent': 'Mozilla/5.0', 'matched': 'select%20'}`

### 6. IP appears across multiple event types and deserves review.

- Severity: `medium`
- Type: `ip.multi_signal`
- Evidence: `{'ip': '198.51.100.22', 'event_types': ['http_request', 'ssh_failed_login']}`

### 7. IP appears across multiple event types and deserves review.

- Severity: `medium`
- Type: `ip.multi_signal`
- Evidence: `{'ip': '203.0.113.10', 'event_types': ['http_request', 'ssh_successful_login']}`

