# ThreatLens AI Incident Report

Generated: 2026-05-18T03:55:06.587724+00:00

## Executive Summary

ThreatLens identified 7 finding(s): 1 critical, 1 high, 5 medium. Key themes: auth.bruteforce, ip.multi_signal, secret.exposure, web.suspicious_request. Priority IPs: 198.51.100.22, 192.0.2.45, 203.0.113.10. Review critical items first, block abusive source IPs where appropriate, rotate exposed credentials, and preserve original logs for incident review.

## Log Intake

- Parsed events: 11
- Findings: 7
- Critical: 1
- High: 1
- Medium: 5

## Priority Queue

1. **critical** - Log line contains credential-like material and should be redacted. (secret.exposure)
2. **high** - Repeated SSH login failures indicate a brute-force attempt. (auth.bruteforce)
3. **medium** - HTTP request matches a suspicious path or scanner signature. (web.suspicious_request)

## IP Risk Table

| IP | Max Severity | Findings | Event Types |
| --- | --- | ---: | --- |
| 198.51.100.22 | high | 4 | http_request, ssh_failed_login |
| 192.0.2.45 | medium | 1 | http_request |
| 203.0.113.10 | medium | 1 | http_request, ssh_successful_login |

## Findings

### 1. Log line contains credential-like material and should be redacted.

- Severity: `critical`
- Type: `secret.exposure`
- Evidence: `source=docker, event_type=docker_activity, raw_preview=2026-05-17T10:10:45Z app: outbound request header Authorization: Bearer demo-token-value-12345`
- Recommended next step: Rotate the exposed credential, redact affected logs, and review downstream access.

### 2. Repeated SSH login failures indicate a brute-force attempt.

- Severity: `high`
- Type: `auth.bruteforce`
- Evidence: `ip=198.51.100.22, failed_attempts=3, users=['admin', 'deploy', 'root']`
- Recommended next step: Block or rate-limit the source IP and verify no successful login followed the failures.

### 3. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `ip=198.51.100.22, path=/.env, status=404, user_agent=sqlmap/1.7, matched=sqlmap`
- Recommended next step: Review the request path, user agent, and response code; add WAF or app rules if needed.

### 4. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `ip=198.51.100.22, path=/wp-admin, status=404, user_agent=Mozilla/5.0, matched=/wp-admin`
- Recommended next step: Review the request path, user agent, and response code; add WAF or app rules if needed.

### 5. HTTP request matches a suspicious path or scanner signature.

- Severity: `medium`
- Type: `web.suspicious_request`
- Evidence: `ip=192.0.2.45, path=/search?q=union%20select%20password, status=403, user_agent=Mozilla/5.0, matched=select%20`
- Recommended next step: Review the request path, user agent, and response code; add WAF or app rules if needed.

### 6. IP appears across multiple event types and deserves review.

- Severity: `medium`
- Type: `ip.multi_signal`
- Evidence: `ip=198.51.100.22, event_types=['http_request', 'ssh_failed_login']`
- Recommended next step: Correlate this IP across auth, web, and infrastructure logs before closing the incident.

### 7. IP appears across multiple event types and deserves review.

- Severity: `medium`
- Type: `ip.multi_signal`
- Evidence: `ip=203.0.113.10, event_types=['http_request', 'ssh_successful_login']`
- Recommended next step: Correlate this IP across auth, web, and infrastructure logs before closing the incident.

