---
title: Decisions
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 25 — Decisions

→ Existing Phase 8A coverage: [[10-Decisions/Architecture Decisions|Architecture Decisions]] · [[10-Decisions/Hybrid Retrieval Weights|Retrieval Weights]] · [[10-Decisions/Local Only Embedding Decision|Local Embedding Decision]]

## Decision Log

| ID | Decision | Phase | Status |
|----|----------|-------|--------|
| dec-local-embeddings | Use local all-MiniLM-L6-v2 for embeddings (no cloud) | 8A | ✅ Active |
| ret-hybrid-weights | Lexical + vector hybrid with tuned weights | 7A/8A | ✅ Active |
| ret-rule-lexical-fallback | Fall back to lexical when vector match is weak | 8A | ✅ Active |
| wade-confidence-threshold | Confidence threshold for surfacing findings | 8A | ✅ Active |
| dec-phi3mini | Use phi3:mini for local LLM inference | 8C | ✅ Active |
| dec-neo4j-wsl2 | Run Neo4j via WSL2 Docker (Docker Desktop blocked) | 8C | ✅ Active |
| dec-null-cross-encoder | Bypass OpenAI reranker with null implementation | 8C | ✅ Active |

## Key Architectural Decisions

**No cloud AI APIs** — All AI inference is local (Ollama + SentenceTransformer). Decision: cost control + data privacy.

**Local-only embeddings** — `all-MiniLM-L6-v2` (384-dim) for LightRAG. `nomic-embed-text` (768-dim) for Graphiti. Decision: no API key dependencies for core intelligence.

**WSL2 Docker workaround** — Docker Desktop Windows pipe exits with `0x40010004`. Workaround: `wsl -d Ubuntu-24.04 -- docker ...`. Decision: unblock Neo4j without requiring Docker Desktop fix.

## See Also

- [[10-Decisions/index|Phase 8A Decisions]] · [[24-Roadmap/index|Roadmap]]
- [[01-Architecture/Phase History|Phase History]]

#webhound #decisions #index
