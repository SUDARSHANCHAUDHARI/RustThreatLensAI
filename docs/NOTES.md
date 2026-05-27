# Notes

## Why This Exists

Security review often starts with a log file and a simple question: does anything look dangerous? RustThreatLensAI gives a local first pass without sending logs anywhere.

## Known Limits

- Detection rules are heuristics, not complete security analysis.
- It can miss threats that do not match the current parser or detector rules.
- It can flag fake or harmless secret-like strings.

## Maintenance Notes

- Keep fixtures synthetic.
- Avoid committing real logs.
- Add tests for every new detector rule.
