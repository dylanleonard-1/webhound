---
title: Executive Reasoning
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Executive Reasoning

Generates customer-safe executive summaries from finding sets. No scare tactics, no unsupported claims, no jargon.

## Location

`scripts/wade/reasoning/executive.py` → `generate_executive_summary(findings)`

## Output: ExecutiveSummary

```python
@dataclass
class ExecutiveSummary:
    overall_posture: str           # e.g. "Needs Attention"
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    top_concerns: list[str]        # customer-safe language
    immediate_actions: list[str]
    positive_observations: list[str]
    narrative: str
    advisory_note: str             # ADVISORY disclaimer
```

## Posture Labels

| Posture | Condition |
|---------|-----------|
| "Critical Issues Found — Immediate Action Required" | ≥3 critical OR (critical + high) |
| "Significant Issues Found" | any critical |
| "Needs Attention" | any high |
| "Minor Improvements Recommended" | any medium |
| "Good Security Posture" | all low/info |

## Customer Language Examples

| Finding Type | Customer Language |
|-------------|-------------------|
| `exposed_env` | "configuration files containing sensitive information were accessible" |
| `cloudflare_challenge_page` | "the site's security provider presented a verification challenge (this is a security feature, not a vulnerability)" |
| `third_party_script_risk` | "third-party scripts from external domains were loaded" |
| `missing_csp` | "a browser security policy controlling which scripts can run was absent" |

## Key Properties

- Provider findings always go to `informational_count` — never reported as vulnerabilities
- `advisory_note` included on every summary
- Positive observations explicitly noted (active WAF = positive)
- Empty finding set returns "No findings to summarize"

## See Also

- [[WADE Reasoning Engine]] · [[Priority Reasoning]] · [[Shadow Mode]]
- [[Finding Correlation]] · [[Attack Chain Modeling]]

#webhound #wade #executive #phase8d
