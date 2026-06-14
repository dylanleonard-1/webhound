---
title: WADE Layer Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# WADE Layer Map

Full picture of WADE's layers, from raw finding to knowledge-enriched output.

## Layer Stack

```
Scanner Output (14 modules)
        ↓
[Layer 1] Per-Finding Confidence Score
  - confidence float on each Finding
  - engine-specific baseline (Nuclei: high, heuristic: medium)
        ↓
[Layer 2] FP Rule Application
  - Suppression rules (user-defined, org-scoped)
  - Provider FP rules (CDN IPs, deployment-protection patterns)
  - Knowledge corpus FP notes (10 false_positive_note records)
        ↓
[Layer 3] Cross-Scan Behavioural Correlation (wade_correlation.py)
  - tech_stack_churn · tls_instability · third_party_explosion
  - persistent_header_regression · admin_surface_flapping
  - Produces BehaviouralAnomaly objects with evidence + rationale
        ↓
[Layer 4] Knowledge Retrieval
  - Hybrid retrieval (lexical + vector) → corpus chunks
  - Returns remediation + taxonomy + threat-intel context
  - Brain v8B: 22 finding types, 1.0 retrieval confidence
        ↓
[Layer 5] Threat Intel Enrichment
  - VirusTotal, GreyNoise reputation
  - ThreatIndicator records linked to findings
        ↓
Output: Scored, grouped, FP-reduced, knowledge-enriched findings
```

## Live vs Pending

| Layer | Status | Notes |
|-------|--------|-------|
| Confidence scoring | ✅ Live | Per finding |
| FP rules | ✅ Live | User + provider |
| Cross-scan correlation | ✅ Live | 5 rules |
| Knowledge retrieval | ✅ Live | Lexical mode |
| Vector retrieval | ✅ Live (LightRAG) | 19 entities indexed |
| Graph retrieval | ✅ Live (Neo4j) | 172 nodes |
| Graphiti memory | ✅ Live | 13 episodes |
| Full graph-enhanced WADE | ⏳ Phase 9A | Future |

## Knowledge Layers

| Source | Records | Notes |
|--------|---------|-------|
| Knowledge corpus | 487 records / 1161 chunks | hybrid retrieval |
| LightRAG graph | 19 entities | [[14-LightRAG/index]] |
| Graphiti episodes | 13 episodes | [[15-Graphiti/index]] |
| Neo4j brain graph | 172 nodes | [[16-Neo4j/index]] |

## See Also

- [[08-WADE/index|WADE Index]] · [[03-WADE/WADE Overview|Phase 8A WADE Overview]]
- [[13-Knowledge Corpus/index|Corpus]] · [[14-LightRAG/index|LightRAG]] · [[15-Graphiti/index|Graphiti]]

#webhound #wade #map
