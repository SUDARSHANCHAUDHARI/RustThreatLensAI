# ThreatLens AI Architecture

ThreatLens AI is currently a dependency-free CLI MVP for safe log investigation. It normalizes auth, nginx, and Docker logs, runs deterministic detectors, and produces analyst-friendly reports.

## Current MVP Flow

```mermaid
flowchart LR
  Logs["Auth / nginx / Docker logs"] --> Parser["Parser services"]
  Parser --> Events["Normalized events JSON"]
  Events --> Detectors["Threat detectors"]
  Detectors --> Findings["Findings JSON"]
  Events --> Risk["IP risk table"]
  Findings --> Summary["Summary provider"]
  Summary --> Reports["Incident + triage reports"]
  Risk --> Reports
```

## Service Boundaries

- `log_parser.py` normalizes log lines into event dictionaries.
- `threat_detector.py` detects brute force, suspicious HTTP, credential exposure, and multi-signal IPs.
- `ai_summary.py` defines the summary provider boundary. The MVP uses a deterministic offline provider.
- `report_generator.py` produces incident, triage, and IP risk views.
- `cli.py` ties the local demo workflow together.

## Future Product Direction

```mermaid
flowchart TB
  Web["React upload UI"] --> API["FastAPI API"]
  API --> Storage["PostgreSQL / object storage"]
  API --> Queue["Worker queue"]
  Queue --> Detectors["Parsers + detectors"]
  Detectors --> Provider["AI summary provider"]
  Provider --> Reports["Incident reports"]
  Reports --> Web
```

Keep the detector and report layers provider-neutral so OpenAI, Claude, or an offline deterministic provider can be swapped without changing parsing logic.
