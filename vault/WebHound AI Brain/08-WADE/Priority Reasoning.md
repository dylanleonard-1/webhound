---
title: Priority Reasoning
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Priority Reasoning

Produces advisory priority recommendations. Does NOT alter production severity.

## Location

`scripts/wade/reasoning/priority.py` → `PriorityReasoner().prioritize(finding)`

## Priority Levels

| Level | Meaning |
|-------|---------|
| `IMMEDIATE` | Investigate/remediate first |
| `HIGH` | Prompt attention in next sprint |
| `MEDIUM` | Schedule for remediation |
| `LOW` | Track but not urgent |

## 6 Scoring Factors

| Factor | Effect |
|--------|--------|
| Exploitability | +0.60 (CRITICAL), +0.30 (HIGH), +0.20 (MEDIUM), +0.10 (LOW) |
| Provider context | −0.20 for known provider-behavior findings |
| Threat intel | +0.15 if `threat_intel_match` present in finding set |
| Attack chain support | +0.10 if part of an identified attack chain |
| Correlation patterns | +0.05 if in a correlation pattern |

## Finding Categories

| Category | Examples | Base Score |
|----------|---------|------------|
| CRITICAL | `exposed_env`, `exposed_git`, `exposed_backup_file` | 0.60 |
| HIGH | `threat_intel_match`, `suspicious_javascript`, `tls_expiry` | 0.30 |
| MEDIUM | `missing_csp`, `missing_hsts`, `tls_misconfiguration` | 0.20 |
| Provider | `cloudflare_challenge_page`, `vercel_deployment_protection` | −0.20 |

## Example

```python
from scripts.wade.reasoning.priority import PriorityReasoner
from scripts.wade.reasoning.models import Finding, PriorityLevel

rec = PriorityReasoner().prioritize(Finding("exposed_env"))
# rec.advisory_priority == PriorityLevel.IMMEDIATE
# rec.advisory_only == True
# rec.explanation.factors contains rationale for each factor
```

## Key Property

**`advisory_only: True` always** — advisory priority is separate from and does not modify production severity.

## See Also

- [[WADE Reasoning Engine]] · [[Root Cause Analysis]] · [[Executive Reasoning]]
- [[Confidence Model]] · [[Shadow Mode]]

#webhound #wade #priority #phase8d
