# Content Plan

## Positioning

RustThreatLensAI is a strong security and solo-dev operations story: local log triage before deeper incident response.

## Blog Post Queue

| Priority | Working Title | Feature Tie-In |
| --- | --- | --- |
| 1 | Scanning Logs Locally for Obvious Security Risks | Current detectors and threshold tuning |
| 2 | How to Design a Simple Brute-Force Detector | Configurable threshold behavior |
| 3 | Why Secrets in Logs Are a Production Bug | Secret-like detection |

## Auto-Blog Prompt Seed

Write a direct technical blog post about local log threat scanning for solo developers. Use RustThreatLensAI as the example. Include a fake auth log, the analyze command, `--brute-force-threshold`, output, and a section explaining why logs should not be uploaded casually.

## Useful Examples

- `examples/auth.sample`
- `threatlens analyze examples/auth.sample --brute-force-threshold 6`
- Secret-like finding example.
