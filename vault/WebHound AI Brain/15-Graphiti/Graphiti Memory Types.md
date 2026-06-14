---
title: Graphiti Memory Types
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Graphiti Memory Types

8 memory types defined in `corpus/exports/graphiti_episode_schema.json`.

## Types

| Memory Type | Purpose |
|-------------|---------|
| `engineering_decision` | Architecture and implementation decisions |
| `scanner_behavior` | How scanner engines behave in specific conditions |
| `provider_behavior` | How providers (Cloudflare, Vercel) respond to scanning |
| `threat_intel_rule` | Threat intelligence classification rules |
| `taxonomy_rule` | Vulnerability taxonomy and severity rules |
| `false_positive_rule` | Rules for identifying and reducing false positives |
| `retrieval_rule` | Rules governing hybrid retrieval behavior |
| `phase_status` | Phase completion status records |

## How Memories Are Used

```
WADE query (finding type)
      ↓
Graphiti.search() → Neo4j vector + graph search
      ↓
Relevant Episodic + Entity nodes retrieved
      ↓
Context injected into WADE reasoning
```

## Episode-to-Type Mapping

| Episode ID | Memory Type |
|------------|-------------|
| dec-local-embeddings | engineering_decision |
| scan-dalfox-confirm-xss | scanner_behavior |
| fp-cloudflare-challenge | false_positive_rule |
| prov-vercel-deployment-protection | provider_behavior |
| ti-greynoise-shared-cdn | threat_intel_rule |
| tax-cwe79-xss | taxonomy_rule |
| wade-confidence-threshold | retrieval_rule |
| ret-hybrid-weights | retrieval_rule |
| phase-8a-status | phase_status |
| bench-phase7a-hybrid | retrieval_rule |
| false-pos-cdn-ip | false_positive_rule |
| ret-rule-lexical-fallback | retrieval_rule |
| phase-8c-status | phase_status |

## See Also

- [[15-Graphiti/index|Graphiti Index]] · [[15-Graphiti/Graphiti Episode Overview|Episodes]]
- [[16-Neo4j/index|Neo4j]] · [[08-WADE/WADE Layer Map|WADE Layer Map]]

#webhound #graphiti #memory-types
