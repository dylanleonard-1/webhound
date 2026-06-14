<!-- WEBHOUND-GENERATED -->
# Phase 8C-INFRA: Local AI Brain Infrastructure Results

**Date:** 2026-06-14
**Branch:** feat/ai-brain-phase-8c-infra-runtime
**Phase:** 8C-INFRA — Local LLM / Docker / Neo4j / Graphiti / LightRAG-graph runtime

---

## STATE OF LOCAL AI BRAIN INFRA

| Component | Status | Blocker |
|-----------|--------|---------|
| Docker daemon | OFFLINE | npipe not found — Desktop not running |
| Docker CLI | LIVE v29.4.2 | — |
| Docker Compose | LIVE v5.1.3 | — |
| Ollama | OFFLINE | Not installed on this host |
| Neo4j | OFFLINE | Docker daemon offline |
| Graphiti runtime | CONFIGURED_PENDING | Neo4j + LLM unavailable |
| LightRAG vector | LIVE | 30 chunks indexed, 5 queries < 3s |
| LightRAG graph | CONFIGURED_PENDING | No Ollama LLM for entity extraction |
| Brain health check | LIVE | Docker/Ollama checks added |

---

## Goal Results

### GOAL 1 — Docker Compose: `docker-compose.ai-brain.yml`

**STATUS: CONFIGURED (daemon offline)**

New compose file created with:
- `neo4j:5-community` with LOCAL DEV ONLY password label (`webhound-brain-local-dev`)
- `ollama/ollama:latest` service on port 11434
- Named volumes gitignored: `neo4j_data/`, `neo4j_logs/`, `ollama_models/`

**Blocker:** Docker daemon repeatedly fails to start in this env (`npipe:////./pipe/dockerDesktopLinuxEngine` not found). Compose file validated for correctness; cannot start containers without daemon.

```bash
# When Docker daemon is running:
docker compose -f docker-compose.ai-brain.yml up -d
```

### GOAL 2 — Ollama Setup: `docs/ai/OLLAMA_SETUP.md`

**STATUS: DOCUMENTED**

Setup doc written with:
- Option A: Native Windows installer (recommended)
- Option B: Docker (when daemon available)
- Option C: WSL2
- Recommended models: `llama3.2` (~2GB) + `nomic-embed-text` (~280MB)
- Troubleshooting table
- Full activation checklist

**Current state:** Ollama NOT INSTALLED on this host (exit=127). Doc provides complete install path.

### GOAL 3 — Neo4j Scripts

**STATUS: OFFLINE (configured, dry-run validated)**

Scripts created:
- `scripts/ai/check_neo4j.py` — bolt:7687 connectivity + Cypher schema validation + reports
- `scripts/ai/load_brain_graph_neo4j.py` — loads Graphify graph (126 nodes, 263 edges) as FileNode + DEPENDS_ON/WIKI_LINK relationships

Dry-run validated:
- `check_neo4j.py --dry-run` → status OFFLINE, report written
- `load_brain_graph_neo4j.py` → 389 Cypher statements generated, validated (no Neo4j required)
- `docs/ai/NEO4J_RUNTIME_RESULTS.md` written with setup guide

**Existing `load_neo4j.py`** (chunks/manifest loader) unchanged — new file adds brain graph layer.

### GOAL 4 — Graphiti Runtime

**STATUS: CONFIGURED_PENDING**

Scripts created:
- `scripts/ai/graphiti_runtime_check.py` — checks graphiti-core, Neo4j port, Ollama port, model list, episode schema; writes `GRAPHITI_RUNTIME_RESULTS.md`
- `scripts/ai/load_graphiti_seed_memories.py` — loads 13 episodes using Ollama OpenAI-compat API (`--live` for real run, default dry-run)

Integration design:
- Uses `graphiti_core.llm_client.OpenAIClient` pointed at `http://localhost:11434/v1` (Ollama)
- Uses `graphiti_core.embedder.openai.OpenAIEmbedder` with `nomic-embed-text` (768-dim)
- `graphiti.add_episode()` with `EpisodeType.text` for all 13 episodes

**Blockers:**
1. Neo4j bolt:7687 — OFFLINE (Docker daemon down)
2. Ollama port:11434 — OFFLINE (not installed)

### GOAL 5 — LightRAG Graph Layer

**STATUS: LIVE (vector) / CONFIGURED_PENDING (graph)**

Script created:
- `scripts/ai/lightrag_graph_runtime_check.py` — checks vector storage, embedding model, Ollama, graph entity count; writes `LIGHTRAG_GRAPH_RUNTIME_RESULTS.md`

Current state:
- **Vector layer: LIVE** — 30 chunks in NanoVectorDB, sentence-transformers all-MiniLM-L6-v2, naive queries working
- **Graph layer: CONFIGURED_PENDING** — stub LLM returned `{"entities":[], "relationships":[]}` during indexing so 0 entities extracted
- Ollama integration documented with code snippet using `lightrag.llm.ollama.ollama_model_complete`

**Unblock path:** Install Ollama + pull `llama3.2` + `nomic-embed-text`, clear `lightrag_storage/`, re-run `build_lightrag_index.py` with real LLM.

### GOAL 6 — Brain Health Upgrade

**STATUS: LIVE**

`scripts/ai/check_brain_health.py` updated with:
- `check_docker()` — runs `docker info`, checks compose file existence
- `check_ollama()` — checks port 11434, queries `/api/tags` for model list
- Both added to `main()` and `write_report()` infra table
- New status icons: `live_no_models`, `not_installed`

Updated health report now shows 10 components (up from 8).

### GOAL 7 — Infrastructure Tests: `tests/ai/test_brain_infra_runtime.py`

**STATUS: LIVE — 25 passed, 2 skipped**

27 tests total:
- 7 file existence tests (always run)
- 5 config validation tests (compose content, gitignore, doc content)
- 4 script import tests (importable + function presence)
- 4 dry-run execution tests (run without live infra)
- 2 episode schema tests (count + field validation)
- 3 graceful offline handling tests
- 1 brain health function test
- 1 Neo4j live test (SKIPPED — bolt:7687 offline)
- 1 Ollama live test (SKIPPED — port:11434 offline)

### GOAL 8 — This Document

Written with honest LIVE / CONFIGURED_PENDING / OFFLINE status per component.

---

## Component Status Summary

| Component | Live? | Notes |
|-----------|-------|-------|
| Hybrid Retrieval (WADE) | LIVE | Lexical + dense, all 22 finding types |
| LightRAG vector | LIVE | 30 chunks, naive mode, local MiniLM |
| Graphify (local equiv) | LIVE | 126 nodes, 263 edges, D3 visualization |
| WADE Retrieval advisory | LIVE | 22 finding types, confidence scoring |
| Brain health check | LIVE | 10 components including infra |
| LightRAG graph | CONFIGURED_PENDING | Needs Ollama LLM for entity extraction |
| Graphiti | CONFIGURED_PENDING | 13 episodes ready; needs Neo4j + Ollama |
| Neo4j | OFFLINE | Docker daemon not running |
| Ollama | OFFLINE | Not installed on this host |
| Docker daemon | OFFLINE | Desktop not started / npipe failure |

---

## Activation Checklist

When Docker is available on this machine:

```bash
# 1. Start Docker Desktop (or ensure daemon is running)
# 2. Start Neo4j + Ollama
docker compose -f docker-compose.ai-brain.yml up -d

# 3. Pull LLM models (~2.3GB total)
docker exec webhound-ollama-dev ollama pull llama3.2
docker exec webhound-ollama-dev ollama pull nomic-embed-text

# 4. Load knowledge graph into Neo4j
.venv-api/Scripts/python scripts/ai/load_neo4j.py
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py --live

# 5. Seed Graphiti memories
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live

# 6. Re-index LightRAG with graph extraction
# (Update build_lightrag_index.py to use ollama_model_complete)
rm -rf lightrag_storage/
.venv-api/Scripts/python scripts/ai/build_lightrag_index.py

# 7. Run full brain health check
.venv-api/Scripts/python scripts/ai/check_brain_health.py
```

---

## Security Verification

- Cloud AI APIs: NONE used (Ollama local only, stub LLM for indexing)
- Customer data: NONE accessed
- WADE scoring engine (`scanner/webhound/wade/`): UNCHANGED
- Provider-access code: UNCHANGED
- `.mcp.json`: UNCHANGED
- Production requirements.txt: UNCHANGED
- Neo4j volumes: gitignored (`neo4j_data/`, `neo4j_logs/`)
- Ollama models volume: gitignored via Docker named volume (not project dir)
- Compose passwords: labeled LOCAL DEV ONLY
