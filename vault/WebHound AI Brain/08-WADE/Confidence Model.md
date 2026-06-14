---
title: Confidence Model
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Confidence Model

8-factor confidence scoring for all advisory reasoning outputs. Every conclusion cites its confidence level and the factors that determined it.

## Location

`scripts/wade/reasoning/confidence.py` → `ConfidenceFactors` + `build_confidence()`

## The 8 Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| `source_authority` | 15% | OWASP/CWE > internal > none |
| `evidence_quality` | 20% | Direct observation vs inference |
| `provider_effects` | 20% | 1.0=clean, <0.5=likely provider FP |
| `finding_consistency` | 10% | Consistent across scans |
| `historical_similarity` | 5% | Matches prior similar findings |
| `threat_intel_corroboration` | 10% | TI confirms the finding |
| `attack_chain_support` | 5% | Finding fits a known attack chain |
| `false_positive_signals` | 15% | 1.0=no FP signals, 0.0=strong FP |

## Confidence Levels

| Level | Score Range | Meaning |
|-------|-------------|---------|
| `HIGH` | ≥ 0.72 | Strong multi-signal confidence |
| `MEDIUM` | 0.50–0.71 | Some evidence but not all signals corroborating |
| `LOW` | 0.30–0.49 | Limited evidence; treat as tentative |
| `INSUFFICIENT` | < 0.30 | Too little evidence to advise |

## Confidence Explanation Examples

**HIGH:** "HIGH: authoritative source (OWASP/CWE); directly observed; consistent across scans; 5 knowledge-corpus chunks supporting"

**LOW (provider):** "LOW because provider WAF/deployment-protection likely affecting observation"

**LOW (FP signals):** "LOW because strong false-positive signals present"

## Retrieval Boosts

- ≥3 retrieval chunks → +0.05 to score
- ≥2 graph nodes → +0.03
- ≥1 memory episode → +0.02

## Provider FP Signals

`cloudflare_challenge_page`, `vercel_deployment_protection`, `provider_blocked_scan` → `provider_effects < 0.5`, `false_positive_signals < 0.5`

## See Also

- [[WADE Reasoning Engine]] · [[Finding Correlation]] · [[Priority Reasoning]]
- [[Graph Reasoning]] · [[Memory Reasoning]]

#webhound #wade #confidence #phase8d
