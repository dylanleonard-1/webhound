---
title: Architecture Decisions
status: active
source: webhound-ai-brain
created: 2026-06-14
phase: 8A
scope: internal
---
<!-- WEBHOUND-GENERATED -->


# Architecture Decisions

1. Local-only embeddings (privacy + cost)
2. Hybrid weights 0.35/0.65 (dense outperforms)
3. Numpy over FAISS (1161 chunks fits in RAM)
4. Append-only manifest (immutable ingestion record)
5. No cloud APIs (all retrieval runs locally)

## See Also

- [[WebHound Architecture Overview]]
- [[Retrieval Modes]]

#decisions #architecture
