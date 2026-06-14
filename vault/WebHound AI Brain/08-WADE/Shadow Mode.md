---
title: Shadow Mode
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
---
<!-- WEBHOUND-GENERATED -->

# Shadow Mode

`WADEShadowReasoner` runs the full advisory reasoning pipeline in parallel with production WADE, producing a `ShadowReasoningPackage` without modifying any production finding.

## Location

`scripts/wade/reasoning/shadow_mode.py` → `WADEShadowReasoner`

## Pipeline

```
findings → WADEShadowReasoner.analyze(findings, scan_id=...)
                    ↓
    correlate_findings()     → CorrelationContext[]
    identify_attack_chains() → AttackChainCandidate[]
    RootCauseReasoner()      → RootCauseResult[]
    PriorityReasoner()       → PriorityRecommendation[]
    generate_executive_summary() → ExecutiveSummary
                    ↓
         ShadowReasoningPackage
         - production_unchanged: True  ← guaranteed
         - as_dict()                   ← JSON-serializable
         - delta_vs_production()       ← compare advisory vs prod
```

## Key Guarantee

```python
pkg = WADEShadowReasoner().analyze(findings)
assert pkg.production_unchanged is True       # always
assert all(c.advisory_only for c in pkg.correlations)
assert all(a.advisory_only for a in pkg.attack_chains)
assert all(r.advisory_only for r in pkg.root_causes)
assert all(p.advisory_only for p in pkg.priority_recommendations)
```

## Delta Comparison

```python
prod_severities = {"exposed_env": "CRITICAL", "missing_hsts": "LOW"}
delta = pkg.delta_vs_production(prod_severities)
# delta["production_unchanged"] == True always
# delta["deltas"] shows where advisory priority differs from prod severity
# No production values are modified
```

## Single Finding

```python
result = WADEShadowReasoner().analyze_single(
    Finding("missing_csp"),
    retrieval_chunks=[...],
    graph_nodes=3,
    memory_episodes=1,
)
# result.production_unchanged is True
# result.advisory_label == "ADVISORY"
```

## See Also

- [[WADE Reasoning Engine]] · [[Finding Correlation]] · [[Attack Chain Modeling]]
- [[Root Cause Analysis]] · [[Priority Reasoning]] · [[Executive Reasoning]]

#webhound #wade #shadow-mode #phase8d
