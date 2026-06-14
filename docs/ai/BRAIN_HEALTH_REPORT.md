<!-- WEBHOUND-GENERATED -->
# WebHound Brain Health Report

**Generated:** 2026-06-14T08:21:58.772565Z
**Overall Status:** HEALTHY — core components live
**WADE Advisory:** READY

## Component Status

| Component | Status | Detail |
|-----------|--------|--------|
| Corpus | OK | 1161 chunks / 487 manifest / 1161 embeddings |
| Vault | OK | 59 notes in 13 sections |
| Hybrid Retrieval | LIVE | 3 hits in 0.245s |
| WADE Retrieval | LIVE | 22 finding types, confidence=1.00 |
| Graphify | LIVE (local) | 126 nodes / 263 edges |
| LightRAG | LIVE_FULL | v1.5.2 — phi3:mini via Ollama (local) |
| Graphiti | READY | v? — Neo4j offline + no local LLM — schema seeded, runtime pending |
| Neo4j | LIVE | bolt:7687 = True —  |

## Corpus Health

```
Manifest records : 487 (expected: 487)
Chunk count      : 1161 (expected: 1161)
LightRAG docs    : 1161 (expected: 1161)
Embedding count  : 1161 (expected: 1161)
Embedding size   : 1741 KB
Graphiti seeds   : OK
```

## Vault Health

```
Notes    : 59
Sections : 13
Sections : 00-Maps, 01-Architecture, 02-Scanner Engines, 03-WADE, 04-Knowledge Corpus, 05-Provider Intelligence, 06-Threat Intelligence, 07-Vulnerability Taxonomy, 08-External Tools, 09-Reports, 10-Decisions, 99-Graphify, WebHound AI Brain
```

## Live vs Configured

| Component | Live? | Blocker |
|-----------|-------|---------|
| Hybrid Retrieval | YES | — |
| WADE Retrieval | YES | — |
| Graphify (local) | YES | Binary unavailable; local equiv used |
| LightRAG vector | YES | Vector only; graph needs local LLM |
| Graphiti | NO — schema seeded | Neo4j + local LLM required |
| Neo4j | NO | Docker daemon offline |

## Ready for WADE Reasoning

YES — all core retrieval components live. WADE can retrieve advisory context for all 22 finding types.

## Infrastructure Status (Phase 8C-INFRA)

| Component | Status | Detail |
|-----------|--------|--------|
| Docker daemon | OFFLINE | compose: docker-compose.ai-brain.yml |
| Ollama LLM | LIVE | models: nomic-embed-text:latest, phi3:mini |

## Recommendations

1. Run `build_graphify.py` if graph.json not present
2. Run `build_lightrag_index.py` to build LightRAG vector index
3. Start Docker + Neo4j + Ollama: `docker compose -f docker-compose.ai-brain.yml up -d`
4. Pull Ollama models: `docker exec webhound-ollama-dev ollama pull llama3.2`
5. See `docs/ai/OLLAMA_SETUP.md` for local LLM activation guide
