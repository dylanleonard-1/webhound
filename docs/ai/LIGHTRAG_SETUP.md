# LightRAG Setup (local prototype)

LightRAG is the **first, simplest** local retrieval engine for the Knowledge Layer:
local chunking + embeddings + a lightweight knowledge graph, runnable over local
files with no external service.

> **Status in this environment: NOT installed.** Phase 4 does **not** force-install
> it. The Phase-4 scripts detect its absence and fall back to a **mock keyword
> retrieval** over local files, so the workflow is demonstrable today.

## What Phase 4 ships
- `scripts/ai/setup_lightrag.sh` — checks prerequisites, explains what's missing,
  and prints the **safe, local** config it *would* use. Does **not** auto-install.
- `scripts/ai/ingest_sample_knowledge.py` — builds a tiny **local** index from
  `knowledge/` + `docs/ai/` + `vault/` (LightRAG if available; else a simple local
  JSON keyword index written under a local, git-ignored working dir).
- `scripts/ai/query_knowledge.py` — answers sample queries from the local index
  (LightRAG if available; else the mock keyword path). **No network, no LLM call.**

## Installing LightRAG (ONLY with explicit approval)
Not done in Phase 4. When approved, install into the dev venv (dev-only), e.g.:
```
.venv-api/Scripts/python -m pip install "lightrag-hku"   # name to be confirmed at install time
```
- Confirm the exact package name + license before installing.
- LightRAG's **LLM/embedding** calls must gate on `WEBHOUND_AI_ENABLED` +
  `ANTHROPIC_API_KEY` (no second AI switch). A local/offline embedding option is
  preferred for the first prototype to avoid any network/LLM dependency.

## Safe local config (the shape, not a live config)
- **Working dir:** a local, **git-ignored** path (e.g. `corpus/.rag_work/` or a temp
  dir) — never commit an index blob.
- **Inputs:** only `knowledge/`, `corpus/normalized/`, `docs/ai/`, `vault/`.
- **No network**, no external embeddings by default, no customer data.
- **Provenance:** every indexed chunk keeps a pointer to its source path /
  manifest `doc_id`.

## Graceful failure
If LightRAG isn't importable, scripts print exactly what's missing + the (un-run)
install command, then either use the mock path (`query_knowledge.py`) or exit 0 with
guidance (`setup_lightrag.sh`). They never crash and never auto-install.
