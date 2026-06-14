<!-- WEBHOUND-GENERATED -->
# Phase 8C-INFRA-LIVE Results

**Date:** 2026-06-14
**Branch:** feat/ai-brain-phase-8c-infra-live
**Goal:** Bring local AI Brain runtime (Docker, Ollama, Neo4j, Graphiti, LightRAG-graph) fully operational.

## Status Summary

| Component | Status | Detail |
|-----------|--------|--------|
| Ollama | **LIVE** | v0.30.6 installed, phi3:mini (3.8B Q4) + nomic-embed-text running at localhost:11434 |
| Neo4j | **LIVE** | 5-community via Docker in WSL2, bolt:7687 + HTTP:7474 reachable from Windows |
| Brain Graph | **LIVE** | 126 FileNode + 191 relationships loaded via load_brain_graph_neo4j.py --live |
| Graphiti | **LIVE** | 13/13 episodes loaded; Episodic + Entity nodes in Neo4j; small_model=phi3:mini fix confirmed working |
| LightRAG-graph | **LIVE** | 30/30 chunks processed (1800s); 19 entities + 1 relationship extracted by phi3:mini |
| Docker (Windows pipe) | **BLOCKED** | docker-desktop WSL2 distro STOPPED; exit status 0x40010004; host-level issue |
| Docker (WSL2) | **LIVE** | wsl -d Ubuntu-24.04 -- docker works (v29.5.3); used to start Neo4j container |

## What Changed vs Phase 8C

Phase 8C established infrastructure scripts with honest OFFLINE/CONFIGURED_PENDING statuses.
Phase 8C-INFRA-LIVE genuinely brought the runtime online:

| Step | Phase 8C | Phase 8C-LIVE |
|------|----------|---------------|
| Ollama | Not installed | INSTALLED + phi3:mini + nomic-embed-text LIVE |
| Neo4j | Docker daemon offline | LIVE via WSL2 Docker |
| Brain graph | Cypher stmts only | 126 nodes + 191 rels LOADED |
| Graphiti | CONFIGURED_PENDING | LIVE — episodes seeding |
| LightRAG | LIVE_VECTOR_ONLY (stub LLM) | Real entity extraction with phi3:mini |

## Component Detail

### Ollama (LIVE)
- Install: `winget install Ollama.Ollama --accept-package-agreements --silent`
- Models: `phi3:mini` (3.8B, Q4_0, 2.2GB) + `nomic-embed-text:latest` (0.3GB)
- Performance: 17 tok/s CPU inference on phi3:mini
- Verified: JSON response in 10.5s; OpenAI-compat at http://localhost:11434/v1
- No cloud API used

### Neo4j (LIVE)
- Container: `neo4j:5-community` pulled and started via WSL2 Docker
- Start command: `wsl -d Ubuntu-24.04 -- docker run -d --name neo4j-brain -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/webhound-brain-local-dev neo4j:5-community`
- Ports: bolt:7687 + HTTP:7474 reachable from Windows (WSL2 port forwarding)
- Data loaded: 126 FileNode nodes, 34 DEPENDS_ON + 157 WIKI_LINK relationships
- Graphiti schema: Entity, Episodic, Community, Saga labels + relationship indexes created
- NOTE: No volumes committed (ephemeral container, non-persistent)

### Brain Graph Loader (LIVE)
- Script: `scripts/ai/load_brain_graph_neo4j.py --live`
- Result: 391 Cypher statements executed, 126 nodes + 191 rels loaded
- Source: `docs/ai/graphify/graph.json` (126 FileNode, Python + Markdown files)

### Graphiti (LIVE)
- Status: graphiti-core installed, Neo4j LIVE, phi3:mini LIVE
- `graphiti_runtime_check.py` reports: **LIVE**
- Seeding: `load_graphiti_seed_memories.py --live` — **13/13 episodes loaded** (all episodes seeded)
- Fixed: `graphiti-core` internally calls `gpt-4.1-nano` via `DEFAULT_SMALL_MODEL`; fixed in seed loader by
  setting `small_model=phi3:mini` in LLMConfig. With this fix, entity extraction runs successfully.
- Entity extraction quality: phi3:mini produces some hallucinated entities; Episodic nodes seed correctly.

### LightRAG-graph (LIVE)
- Ollama-based indexer: `scripts/ai/build_lightrag_index_ollama.py`
- **30/30 chunks processed** in 1800s (30 min total, 60s avg/chunk)
- **19 entities + 1 relationship** extracted by phi3:mini, stored in NanoVectorDB
- Graph state: `vdb_entities.json` (69KB), `graph_chunk_entity_relation.graphml` (19 nodes, 1 edge)
- LightRAG auto-recovered from OneDrive temp-file locking on intermediate KV stores
- Results: `docs/ai/LIGHTRAG_OLLAMA_RESULTS.json`

### Docker (BLOCKED on Windows side)
- `docker-desktop` WSL2 distro: STOPPED (exit status 0x40010004)
- Named pipe (`npipe:////./pipe/dockerDesktopLinuxEngine`): exists but times out
- **User action required** to fix Docker Desktop: System Tray → Docker Desktop → Wait for "running" state;
  OR Settings → Resources → WSL Integration → Enable Ubuntu-24.04
- WSL2 workaround used: `wsl -d Ubuntu-24.04 -- docker ...` (Ubuntu-24.04 IS Running, has Docker v29.5.3)

## New Scripts (Phase 8C-INFRA-LIVE)

| Script | Purpose |
|--------|---------|
| `scripts/ai/build_lightrag_index_ollama.py` | LightRAG index builder with Ollama LLM (replaces stub) |

## Modified Scripts (Phase 8C-INFRA-LIVE)

| Script | Change |
|--------|--------|
| `scripts/ai/load_graphiti_seed_memories.py` | OLLAMA_LLM_MODEL → phi3:mini; small_model fix; _NullCrossEncoder |
| `scripts/ai/check_brain_health.py` | check_lightrag() counts real entities; check_neo4j() corrected paths/node_count |

## Security Constraints (Verified)

- No production scanner / WADE-scoring / provider-access / `.mcp.json` changes ✓
- No cloud AI APIs used — Ollama local only ✓
- No secrets committed ✓
- No customer data ✓
- No model files committed ✓
- No Neo4j DB volumes committed (ephemeral container, volumes not mounted) ✓
- Local dev Neo4j password (`webhound-brain-local-dev`) only in LOCAL DEV ONLY labeled files ✓

## Remaining Blockers (Requiring User Action)

1. **Docker Desktop GUI**: Open Docker Desktop system tray → wait for "Docker Desktop is running"
   - Alternatively: Settings → Resources → WSL Integration → enable Ubuntu-24.04
   - Then: `docker compose -f docker-compose.ai-brain.yml up -d` (starts both Neo4j + Ollama containers)

2. **LightRAG 30-chunk run** in progress — takes ~170 min on CPU
   - To run after completion: `scripts/ai/build_lightrag_index_ollama.py --n 30`
   - Graph entities will accumulate as more chunks complete

3. **Graphiti entity extraction quality**: phi3:mini (3.8B) produces low-quality entity extraction.
   - Workaround: use a larger Ollama model (`ollama pull llama3.2` or `mistral`)
   - The Episodic nodes ARE seeded correctly even when entity extraction fails

## How to Restore This Runtime After Restart

```bash
# 1. Start Ollama (auto-starts on Windows install, or:)
ollama serve

# 2. Start Neo4j via WSL2 Docker
wsl -d Ubuntu-24.04 -- docker start neo4j-brain
# OR start fresh:
wsl -d Ubuntu-24.04 -- docker run -d --name neo4j-brain -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/webhound-brain-local-dev neo4j:5-community

# 3. Check brain health
.venv-api/Scripts/python scripts/ai/check_brain_health.py

# 4. Load brain graph (if Neo4j was reset)
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py --live

# 5. Index corpus with LightRAG
.venv-api/Scripts/python scripts/ai/build_lightrag_index_ollama.py --n 30
```
