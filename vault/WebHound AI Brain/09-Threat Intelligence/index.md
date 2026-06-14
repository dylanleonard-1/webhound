---
title: Threat Intelligence
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 09 — Threat Intelligence

→ Existing Phase 8A coverage: [[06-Threat Intelligence/Threat Intelligence Overview|TI Overview]] · [[06-Threat Intelligence/TI Sources|TI Sources]] · [[06-Threat Intelligence/VirusTotal Integration|VirusTotal]]

## TI Sources in Knowledge Corpus

| Source | Records | Role |
|--------|---------|------|
| Internal TI rules | 9 official_threat_intel_doc | Curated TI canon |
| GreyNoise | Engine notes | Shared CDN IP classification |
| VirusTotal | Integration docs | Domain/IP reputation |

## Live Integration Points

- `apps/api/services/threat_intel.py` — enrichment service
- `apps/api/models/threat_indicator.py` — `ThreatIndicator` record
- Scanner Engine: [[07-Scanner/Engine - Threat Intel|Threat Intel Engine]]

## Key Rule: GreyNoise CDN Classification

GreyNoise classifies CDN-shared IPs as "noise" — WebHound uses this to avoid false positives on shared infrastructure:
- Episode `ti-greynoise-shared-cdn` in Graphiti memory
- [[15-Graphiti/index|Graphiti]]

## See Also

- [[07-Scanner/Engine - Threat Intel|Scanner TI Engine]] · [[08-WADE/index|WADE]]
- [[10-Providers/index|Providers]] · [[13-Knowledge Corpus/index|Corpus]]

#webhound #threat-intel #index
