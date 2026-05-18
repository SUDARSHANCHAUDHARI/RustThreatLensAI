# Security Notes

ThreatLens AI is defensive and analysis-focused.

## Safe Use

- Analyze only logs you own or are authorized to review.
- Do not upload private production logs to external AI providers without approval.
- Redact secrets before sharing reports.
- Preserve original logs for incident review.
- Treat `secret.exposure` findings as urgent until credentials are rotated.

## Data Handling

- The MVP runs offline and does not call external AI services.
- The sample logs are synthetic and use documentation IP ranges.
- Reports include raw previews for credential exposure; use this only with safe sample data or redacted internal workflows.

## Future Provider Safety

When adding OpenAI or Claude support:

- Send summarized findings instead of full raw logs by default.
- Add explicit user consent before external calls.
- Add a redaction pass before prompt construction.
- Log provider name, timestamp, and prompt version for auditability.
