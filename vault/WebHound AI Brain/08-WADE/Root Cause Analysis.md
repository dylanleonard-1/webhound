---
title: Root Cause Analysis
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Root Cause Analysis

Identifies likely root causes for individual findings and finding clusters. Advisory only.

## Location

`scripts/wade/reasoning/root_cause.py` → `RootCauseReasoner().analyse(findings)`

## Root Cause Patterns

| Category | Trigger | Root Cause |
|----------|---------|------------|
| `deploy_misconfiguration` | ≥2 missing headers | CDN/proxy not setting security headers |
| `provider_behavior` | any provider finding | WAF/deployment-protection masking scan |
| `secret_exposure` | any `exposed_*` finding | Deployment copying sensitive files to web root |
| `deprecated_stack` | TLS issues or old CMS | Stack not maintained; no cert auto-renewal |
| `api_misconfiguration` | GraphQL/Swagger/API exposure | Framework defaults left enabled in production |

## Output: RootCauseResult

```python
@dataclass
class RootCauseResult:
    summary: RootCauseSummary   # root_cause, category, description, remediation_hint
    confidence: RootCauseConfidence
    evidence: list[RootCauseEvidence]
    advisory_only: bool = True
```

## Example: Deploy Misconfiguration

**Trigger:** `missing_csp` + `missing_hsts` + `missing_x_frame_options`

**Root Cause:** CDN/reverse-proxy configuration missing security header defaults

**Remediation Hint:** Add headers at CDN/reverse-proxy layer (Cloudflare Transform Rules, Vercel headers config, nginx add_header) so ALL responses carry them. Audit the deployment that started the regression.

## Example: Provider Behavior

**Trigger:** `cloudflare_challenge_page` or `vercel_deployment_protection`

**Root Cause:** Provider WAF/deployment protection masking scan coverage — NOT a customer vulnerability.

**Remediation Hint:** Add scanner IP to WAF allowlist or configure scanner-specific bypass header.

## Key Properties

- Every result includes `remediation_hint`
- `advisory_only: True` always
- Provider behavior is explicitly identified as non-customer-risk

## See Also

- [[Finding Correlation]] · [[WADE Reasoning Engine]] · [[Priority Reasoning]]
- [[Attack Chain Modeling]] · [[Confidence Model]]

#webhound #wade #root-cause #phase8d
