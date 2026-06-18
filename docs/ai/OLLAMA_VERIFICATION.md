# Ollama Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only). Per instructions, a down service is reported, **not started**.

## Status: ❌ DOWN / NOT RUNNING

| Check | Result |
|-------|--------|
| `ollama` binary on PATH (WSL) | ❌ not found |
| API `http://localhost:11434/api/tags` | ❌ HTTP 000 (connection refused) |
| Running process | ❌ none |

Earlier this session Ollama was live with `phi3:mini` + `nomic-embed-text`; it is **not running now**. Models are not currently enumerable (daemon down). Not started (per VERIFICATION-ONLY scope).

## Documented/expected models

`phi3:mini` (3.8B chat — used for Graphiti/LightRAG entity extraction) and `nomic-embed-text` (embeddings) — per `docs/ai/graphiti_runtime.json` / `lightrag_graph_runtime.json` snapshots (2026-06-14).

## Consumers — what depends on Ollama

| Consumer | Depends on Ollama? | Impact while down |
|----------|--------------------|-------------------|
| **Graphiti** (entity extraction + semantic retrieval) | ✅ YES | retrieval offline; extraction can't run |
| **LightRAG** (graph extraction; `build_lightrag_index_ollama.py`) | ✅ YES | graph build offline |
| **Brain health monitor** (`scripts/ai/check_brain_health.py`) | ✅ checks it | reports Ollama down |
| **Corpus hybrid retrieval** (`scripts/ai/hybrid_retrieval.py`) | ❌ NO | **unaffected** — uses local sentence-transformers, not Ollama |
| **Production scanner / WADE / API** | ❌ NO | **unaffected** — zero production dependency on Ollama |

## Answer: what depends on Ollama today?

Only the **advisory graph experiments** (Graphiti, LightRAG graph mode) depend on Ollama. The **working knowledge retrieval (corpus hybrid index)** and the **entire production product** do **not**. So Ollama being down degrades only the already-weak graph layer — it does not affect customers or the real retrieval path.

**Score: 0% operational** (down) / capability documented. **Criticality: LOW** — nothing production or retrieval-critical depends on it.
</content>
