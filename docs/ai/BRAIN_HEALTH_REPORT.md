<!-- WEBHOUND-GENERATED -->
# WebHound Brain Health Report

**Generated:** 2026-06-14T06:25:52.647709Z
**Overall Status:** HEALTHY — core components live
**WADE Advisory:** READY

## Component Status

| Component | Status | Detail |
|-----------|--------|--------|
| Corpus | OK | 1161 chunks / 487 manifest / 1161 embeddings |
| Vault | OK | 58 notes in 13 sections |
| Hybrid Retrieval | LIVE | 3 hits in 0.226s |
| WADE Retrieval | LIVE | 22 finding types, confidence=1.00 |
| Graphify | LIVE (local) | 126 nodes / 263 edges |
| LightRAG | LIVE (vector) | v1.5.2 — stub (no cloud, no local LLM) — graph extraction skipped |
| Graphiti | CONFIGURED | v? — Neo4j offline + no local LLM — schema seeded, runtime pending |
| Neo4j | OFFLINE | bolt:7687 = False — Docker daemon not running in this env — compose provided |

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
Notes    : 58
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

## Recommendations

1. Run `build_graphify.py` if graph.json not present
2. Run `build_lightrag_index.py --sample 200` to build LightRAG vector index
3. Start Docker + Neo4j: `docker compose -f docker-compose-neo4j.yml up -d`
4. Install Ollama for local LLM to activate Graphiti + LightRAG graph layers
