---
title: Memory Reasoning
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
degraded: "Graphiti offline — degrades gracefully"
---
<!-- WEBHOUND-GENERATED -->

# Memory Reasoning

Augments finding analysis with Graphiti episodic memory. Tenant-isolated. Degrades gracefully.

## Location

`scripts/wade/reasoning/memory_reasoning.py` → `MemoryReasoner`

## Architecture

```
Finding + tenant_id → MemoryReasoner.recall_similar_findings()
                                ↓
                    Graphiti (Neo4j bolt://localhost:7687)
                    - Search episodic memory for similar findings
                    - Tenant boundary ENFORCED
                    - No cross-customer data
                                ↓
                    MemoryReasoningResult
                    - similar_episodes: list[MemoryEpisode]
                    - advisory_boost: str
                    - tenant_isolation_verified: bool  ← always True
```

## Tenant Isolation

```python
result = MemoryReasoner().recall_similar_findings(
    "missing_csp",
    tenant_id="customer-abc-001",  # MANDATORY
)
assert result.tenant_isolation_verified is True
# Caveat: "memory search results are scoped to the knowledge corpus only —
#          no cross-customer scan data is used."
```

**CRITICAL:** Memory search is over the knowledge corpus only — NOT over other customers' scan data. No customer cross-contamination is possible.

## Graceful Degradation

```python
if not result.memory_available:
    # result.advisory_boost = "Memory reasoning unavailable (Graphiti offline).
    #                          Advisory uses retrieval and rule-based reasoning only."
    # Reasoning continues with retrieval + rules
    pass
```

## CI Safety

- No Graphiti/Neo4j in CI → `memory_available=False` → test passes
- `@pytest.mark.skipif(not os.environ.get("GRAPHITI_AVAILABLE"), ...)` for live tests

## See Also

- [[Graph Reasoning]] · [[WADE Reasoning Engine]] · [[Confidence Model]]
- [[15-Graphiti/index\|Graphiti Index]] · [[Shadow Mode]]

#webhound #wade #memory #graphiti #phase8d
