---
title: WADE Reasoning Engine
phase: 8D
created: 2026-06-14
status: LIVE_ADVISORY
scope: advisory
---
<!-- WEBHOUND-GENERATED -->

# WADE Reasoning Engine

Phase 8D advisory layer. Turns WADE from retrieval into reasoning. **Does NOT modify production scoring, severity, confidence, or finding status.**

## Architecture

```
                     ┌──────────────────────────────────┐
Production WADE  ──► │   WADEShadowReasoner (shadow)    │ ──► ShadowReasoningPackage
(unchanged)          │   - correlate_findings()          │     (advisory only)
                     │   - identify_attack_chains()      │
                     │   - RootCauseReasoner.analyse()   │
                     │   - PriorityReasoner.prioritize() │
                     │   - generate_executive_summary()  │
                     └──────────────────────────────────┘
                                    │
                     ┌─────────────▼───────────────────┐
                     │   Knowledge Sources (advisory)  │
                     │   - Hybrid retrieval corpus     │
                     │   - Neo4j graph (optional)      │
                     │   - Graphiti memory (optional)  │
                     └─────────────────────────────────┘
```

## Components

| Component | File | Purpose |
|-----------|------|---------|
| Models | `models.py` | Core dataclasses (Finding, ReasoningResult, etc.) |
| Confidence | `confidence.py` | 8-factor confidence scoring |
| Correlation | `correlation.py` | Multi-finding pattern correlation |
| Attack Chain | `attack_chain.py` | Attack chain candidate modeling |
| Root Cause | `root_cause.py` | Root cause identification |
| Priority | `priority.py` | Advisory priority (not severity) |
| Executive | `executive.py` | Customer-safe executive summaries |
| Graph | `graph_reasoning.py` | Neo4j-backed graph context |
| Memory | `memory_reasoning.py` | Graphiti episodic memory |
| Shadow | `shadow_mode.py` | Full pipeline shadow wrapper |

## Graceful Degradation

| Service | If Down | Behavior |
|---------|---------|---------|
| Neo4j | Offline | `graph_available=False`; reasoning uses retrieval only |
| Graphiti | Offline | `memory_available=False`; reasoning uses retrieval only |
| Dense embeddings | Absent | Falls back to lexical retrieval |
| All services | Down | Pure rule-based reasoning still functions |

## Hard Constraints

- `production_unchanged: True` on every output object
- `advisory_only: True` on every correlation, chain, root cause, priority
- No cloud AI APIs — local Ollama only
- No customer cross-contamination (tenant isolation mandatory)
- No scanner/WADE-scoring/provider-access/`.mcp.json` changes

## See Also

- [[Finding Correlation]] · [[Attack Chain Modeling]] · [[Root Cause Analysis]]
- [[Confidence Model]] · [[Priority Reasoning]] · [[Executive Reasoning]]
- [[Graph Reasoning]] · [[Memory Reasoning]] · [[Shadow Mode]]
- [[WADE Layer Map]] · [[08-WADE/index|WADE Index]]

#webhound #wade #reasoning #phase8d
