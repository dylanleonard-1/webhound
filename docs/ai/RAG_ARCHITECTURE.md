# RAG / Retrieval Architecture

How the AI Knowledge Layer turns provenance-stamped evidence into something Claude
can retrieve and reason over — **locally, infrastructure-first**. Phase 4 is
**architecture + safe scripts + tiny tests**, not population. No external ingestion.

## The five planes
```
1. raw evidence       corpus/raw/**            immutable, as-fetched, hashed
2. normalized         corpus/normalized/**     cleaned + chunked, lineage→raw
3. knowledge graph    corpus/graph/  (+ LightRAG graph)   edges by manifest doc_id
4. operator vault     vault/ + knowledge/      human-curated, pointer-first
5. Claude memory      (compact summaries + pointers ONLY)
```
- **Plane 1 → 2 → 3** is the evidence/retrieval pipeline (built in Phase 5+).
- **Plane 4** is the curated, human-reviewed layer (Phase 3).
- **Plane 5** is durable, compact memory — **summaries + `doc_id`/path pointers
  only**, never full docs/raw feeds/secrets (see `CLAUDE_MEMORY_POLICY.md`).

Provenance survives every plane (see
[`corpus/.../PROVENANCE_POLICY`](corpus/PROVENANCE_POLICY.md)). Every retrievable
chunk traces to a manifest record; every memory summary points to `doc_id`s.

## Why LightRAG first
- **Simplest local prototype.** LightRAG gives local chunking + embedding + a
  lightweight knowledge graph in one library, runnable against local files with no
  external service. It matches "infrastructure, not population."
- **No server to operate.** Unlike a vector DB service, the first prototype can be a
  local index over `knowledge/`, `corpus/`, `docs/ai/`, `vault/`.
- **Status:** LightRAG is **NOT installed** in this environment. Phase-4 scripts
  therefore **fail gracefully** and provide a **mock keyword-retrieval fallback**
  over local files so the flow is demonstrable without installing anything. See
  `LIGHTRAG_SETUP.md`.

## Why Qdrant is deferred
- Qdrant is a separate **server** (typically Docker). Docker was not responding in
  this environment, and `qdrant_client` is not installed. Per the approved decision,
  **Qdrant is future-optional** — not required unless the env clearly supports it
  safely. See `QDRANT_FUTURE_OPTION.md`.

## Reuse, not rebuild
- **Security Graph** (`scanner/webhound/graph/`) is reused **read-only, one-way**
  (per-scan runtime graph → Knowledge Layer later). It is **not** the RAG graph and
  the Knowledge Layer does **not** control scanner/severity/suppression/WADE. See
  `SECURITY_GRAPH_BRIDGE.md`.
- **AI usage** gates on the existing `WEBHOUND_AI_ENABLED` + `ANTHROPIC_API_KEY`
  (`apps/api/config.py`) — **no second AI enablement system**. Phase-4 scripts do
  **not** call any LLM; embeddings/LLM calls are a later, gated step.

## Local-only guarantee (Phase 4)
All Phase-4 scripts operate **only** on local `knowledge/`, `corpus/`, `docs/ai/`,
`vault/`. No web crawling, no threat-feed fetching, no customer data, no secrets, no
production DB. If a heavy dependency is missing, scripts explain what's missing and
exit cleanly.

## Related
`LIGHTRAG_SETUP.md` · `QDRANT_FUTURE_OPTION.md` · `GRAPH_SCHEMA.md` ·
`SECURITY_GRAPH_BRIDGE.md` · `CLAUDE_MEMORY_POLICY.md` · `OBSIDIAN_VAULT_PLAN.md`.
