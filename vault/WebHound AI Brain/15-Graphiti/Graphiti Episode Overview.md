---
title: Graphiti Episode Overview
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Graphiti Episode Overview

13 episodes define the core WebHound knowledge memories seeded into the Graphiti knowledge graph.

## Episodes

| ID | Type | Summary |
|----|------|---------|
| dec-local-embeddings | engineering_decision | Local-only embedding model decision (all-MiniLM-L6-v2) |
| scan-dalfox-confirm-xss | scanner_behavior | DalFox confirms XSS before surfacing as finding |
| fp-cloudflare-challenge | false_positive_rule | Cloudflare challenge page creates FP on form/JS checks |
| prov-vercel-deployment-protection | provider_behavior | Vercel deployment protection blocks scanner by default |
| ti-greynoise-shared-cdn | threat_intel_rule | GreyNoise CDN IPs should not trigger compromise findings |
| tax-cwe79-xss | taxonomy_rule | XSS findings map to CWE-79 |
| wade-confidence-threshold | retrieval_rule | WADE confidence threshold for surfacing findings |
| ret-hybrid-weights | retrieval_rule | Hybrid retrieval weights (lexical vs vector) |
| phase-8a-status | phase_status | Phase 8A Knowledge Layer completion status |
| bench-phase7a-hybrid | retrieval_rule | Phase 7A hybrid retrieval benchmark results |
| false-pos-cdn-ip | false_positive_rule | CDN-shared IPs produce FP on infrastructure checks |
| ret-rule-lexical-fallback | retrieval_rule | Fall back to lexical when vector match is weak |
| phase-8c-status | phase_status | Phase 8C-INFRA-LIVE completion status |

## Seeding

Seeded via `scripts/ai/load_graphiti_seed_memories.py --live`:
- Requires Neo4j + Ollama live
- `phi3:mini` for entity extraction, `nomic-embed-text` for embeddings
- All 13/13 loaded (Phase 8C-INFRA-LIVE)

## Resulting Neo4j State

- **Episodic** nodes: 19 (multiple seeder runs)
- **Entity** nodes: 27 (extracted by phi3:mini)
- **FileNode** nodes: 126 (brain graph)

## Restore Seeding

```bash
# Start services
wsl -d Ubuntu-24.04 -- docker start neo4j-brain
# ollama is auto-started on Windows

# Re-seed
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live
```

## See Also

- [[15-Graphiti/index|Graphiti Index]] · [[15-Graphiti/Graphiti Memory Types|Memory Types]]
- [[16-Neo4j/index|Neo4j]] · [[17-Ollama/index|Ollama]]

#webhound #graphiti #episodes
