# Qdrant — Future Option (deferred)

Qdrant is a dedicated vector-search **server**. It is a **future, optional** backend
for the Knowledge Layer — **not** required for Phase 4, and **not** stood up here.

## Why deferred (per approved decision)
- Qdrant runs as a **separate service** (typically a Docker container). In this
  environment **Docker was not responding**, and `qdrant_client` is **not
  installed**.
- LightRAG (local, no server) is the approved first prototype. Qdrant is only worth
  adding if/when the corpus grows beyond what a local index handles well, **and** the
  environment clearly supports running it safely.

## When to revisit
Consider Qdrant later if all of these hold:
1. The corpus is large enough that local LightRAG retrieval is too slow/limited.
2. Docker (or a managed Qdrant) is reliably available.
3. There's an approved phase to operate a service (ops, backups, security).

## If adopted later (the shape, not a setup)
- Run as a **local container**, bound to localhost; no public exposure.
- Store only **normalized chunks + manifest metadata** (never raw secrets/customer
  data).
- Keep provenance (`doc_id`, source path, authority tier) on every point.
- Embeddings/LLM still gate on `WEBHOUND_AI_ENABLED` + `ANTHROPIC_API_KEY`.

## Phase-4 stance
No Qdrant install, no `qdrant_client` dependency added, no container started. This
doc records the deferral and the conditions to reconsider.
