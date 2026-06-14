---
title: Graph Reasoning
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
degraded: "Neo4j offline — degrades gracefully"
---
<!-- WEBHOUND-GENERATED -->

# Graph Reasoning

Augments finding analysis with Neo4j brain graph context. Degrades gracefully when Neo4j is offline.

## Location

`scripts/wade/reasoning/graph_reasoning.py` → `GraphReasoner`

## Architecture

```
Finding → GraphReasoner.get_cwe_related_findings(finding_type)
                ↓
        Neo4j brain graph (bolt://localhost:7687)
        - FileNode nodes (knowledge corpus entries)
        - Relationships: RELATED, MENTIONS, etc.
                ↓
        GraphReasoningResult
        - related_nodes: list[GraphNode]
        - relationships: list[GraphRelationship]
        - evidence: list[ReasoningEvidence]   ← cites node IDs + rel types
        - advisory_summary: str               ← human-readable
```

## Graceful Degradation

```python
g = GraphReasoner()  # tries bolt://localhost:7687
result = g.get_cwe_related_findings("missing_csp")

if not result.graph_available:
    # result.advisory_summary = "Graph reasoning unavailable (Neo4j offline)"
    # result.caveats = ["Neo4j not reachable — graph context not available"]
    # reasoning continues with retrieval + rules only
    pass
```

## Explainability Requirement

Every graph conclusion cites:
- Node IDs used
- Relationship types traversed
- Advisory summary describing what was found

No black-box graph outputs.

## CI Safety

- No Neo4j available in CI → `graph_available=False` → test passes (skip or degrade)
- `@pytest.mark.skipif(os.environ.get("NEO4J_AVAILABLE") != "1", ...)` for live tests

## Available Methods

| Method | Purpose |
|--------|---------|
| `get_cwe_related_findings(finding_type)` | Query graph for CWE/taxonomy nodes |
| `get_provider_graph_context(provider)` | Query graph for provider context nodes |

## See Also

- [[Memory Reasoning]] · [[WADE Reasoning Engine]] · [[Confidence Model]]
- [[16-Neo4j/index\|Neo4j Index]] · [[Shadow Mode]]

#webhound #wade #graph #neo4j #phase8d
