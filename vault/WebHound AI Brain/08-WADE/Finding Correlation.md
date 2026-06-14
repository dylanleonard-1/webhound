---
title: Finding Correlation
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Finding Correlation

Multi-finding correlation identifies compound security patterns invisible to per-finding analysis.

## Location

`scripts/wade/reasoning/correlation.py` → `correlate_findings(findings)`

## Correlation Patterns

| Pattern | Required Findings | Optional | Confidence |
|---------|------------------|----------|------------|
| `supply_chain_exposure` | `missing_csp` + `third_party_script_risk` | `graphql_exposure` | HIGH (0.82) |
| `session_protection_weakness` | `missing_secure_cookie` + `missing_httponly_cookie` | `missing_hsts`, `missing_samesite_cookie` | HIGH (0.80) |
| `elevated_compromise_risk` | any `exposed_*` + `threat_intel_match` | `graphql_exposure`, `swagger_exposure` | MEDIUM (0.68) |
| `tls_downgrade_cluster` | `tls_misconfiguration` + any TLS signal | `missing_hsts`, `mixed_content` | MEDIUM (0.72) |

## Output: CorrelationContext

```python
@dataclass
class CorrelationContext:
    pattern_name: str
    matched_findings: list[str]
    explanation: CorrelationExplanation  # summary, detail, chain, caveats
    confidence: CorrelationConfidence    # level, score, rationale
    advisory_only: bool = True           # always True
```

## Example

```python
from scripts.wade.reasoning import correlate_findings, Finding

findings = [
    Finding("missing_csp"),
    Finding("third_party_script_risk"),
]
correlations = correlate_findings(findings)
# → [CorrelationContext(pattern_name="supply_chain_exposure", ...)]
```

## Key Properties

- Every `CorrelationContext` has `advisory_only=True`
- Every explanation includes a `ReasoningChain` (step-by-step reasoning path)
- Caveats are explicit (e.g. "TI match may be shared CDN IP")
- Production findings are never modified

## See Also

- [[WADE Reasoning Engine]] · [[Attack Chain Modeling]] · [[Root Cause Analysis]]
- [[Confidence Model]] · [[Shadow Mode]]

#webhound #wade #correlation #phase8d
