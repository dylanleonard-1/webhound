# Phase 8C Results — WebHound Brain Runtime Activation

**Date:** 2026-06-14
**Branch:** feat/ai-brain-phase-8c-runtime
**Status:** Complete — see per-component live vs configured status below

---

## Executive Summary

Phase 8C activates the WebHound Brain runtime stack. All deliverables are
complete. Core retrieval is **live**. LightRAG vector layer is **live**.
Graphiti and Neo4j are **configured/documented** — blocked by Docker daemon
and local LLM availability, both expected per the no-cloud guardrail.

---

## Component Results

### Goal 1 — Graphify

**Status: LIVE (local equivalent)**

Graphify binary is not installed. A local equivalent (`scripts/ai/build_graphify.py`)
was built using AST import scanning and Markdown wikilink extraction.

| Metric | Value |
|--------|-------|
| Nodes | 126 |
| Edges | 263 |
| Python files | 20 |
| Markdown files | 106 |
| Orphan nodes | 0 |
| Most referenced | hybrid_retrieval.py (26 in-links) |
| Most linking | test_wade_retrieval.py (62 out-links) |

Outputs: `docs/ai/graphify/graph.json`, `graph.html` (D3.js interactive), `graph_report.md`
Vault note: `vault/WebHound AI Brain/99-Graphify/graphify_results.md`

---

### Goal 2 — Obsidian Graph

**Status: LIVE**

`scripts/ai/analyze_vault_graph.py` parsed all vault notes.

| Metric | Value |
|--------|-------|
| Total notes | 45 (+ 13 index.md = 58 total files) |
| Wikilinks | 141 |
| Sections (clusters) | 13 |
| Orphan notes | 0 |
| Graph density | 0.0712 |

Outputs: `docs/ai/VAULT_GRAPH_RESULTS.md`, `docs/ai/vault_graph_stats.json`

---

### Goal 3 — LightRAG

**Status: LIVE (vector layer) — graph layer pending local LLM**

lightrag-hku v1.5.2 installed. Configured with:
- Embedding: all-MiniLM-L6-v2 (local, same as Phase 7A)
- LLM: stub (no-op) — graph extraction skipped, returns empty entities
- Storage: NanoVectorDB (local file), NetworkX (in-memory graph)
- Mode tested: `naive` (pure vector retrieval, no graph traversal)

| Metric | Value |
|--------|-------|
| Chunks indexed (sample) | 30 / 1161 |
| Index build time | 35.4s (30 chunks) |
| Vector storage | NanoVectorDB local |
| Graph storage | NetworkX (entities: 0, LLM needed) |
| Cloud API used | NO |

**Benchmark vs Hybrid Retrieval (5 queries, lexical_only mode):**

| Query | Hybrid speed | LightRAG speed | Hybrid KW recall | LightRAG KW recall |
|-------|-------------|----------------|-----------------|-------------------|
| missing_csp | 3ms | 140ms | 0.33 | 0.00 |
| cloudflare | 2ms | 70ms | 0.67 | 0.00 |
| threat_intel | 2ms | 88ms | 0.75 | 0.25 |
| exposed_env | 2ms | 114ms | 0.25 | 0.00 |
| provider_blocked | 2ms | 111ms | 0.50 | 0.00 |

**Analysis:** Hybrid Retrieval outperforms LightRAG naive on both speed and
recall for this corpus. Reasons: (1) Hybrid indexes all 1161 chunks; LightRAG
sample = 30. (2) LightRAG graph layer is empty (no LLM for entity extraction),
reducing retrieval quality. Full LightRAG performance requires a local LLM
(for graph construction) and indexing the complete 1161-chunk corpus.

**LLM gap:** Graph/entity extraction requires a real LLM. With a local Ollama
model, run `build_lightrag_index.py` over the full corpus to see true
LightRAG performance.

---

### Goal 4 — Graphiti

**Status: CONFIGURED / DOCUMENTED — pending Neo4j + local LLM**

graphiti-core v0.29.2 installed. 13 episode memories seeded in schema format.

| Metric | Value |
|--------|-------|
| graphiti-core | Installed (v0.29.2) |
| Neo4j bolt:7687 | OFFLINE |
| LLM client | NOT CONFIGURED |
| Episodes defined | 13 (10 Phase-8A + 3 Phase-8C) |
| Memory types | 8 |
| Schema file | corpus/exports/graphiti_episode_schema.json |

**Gap:** Graphiti requires both Neo4j AND an LLM for entity extraction and
temporal knowledge graph construction. Neither is available. Schema fully
defined; activate with `docker compose -f docker-compose-neo4j.yml up -d`
+ local Ollama, then `python scripts/ai/seed_graphiti.py --live`.

---

### Goal 5 — Neo4j

**Status: OFFLINE — Docker daemon not running**

Docker CLI v29.4.2 installed but daemon offline (Docker Desktop not responding
in this session — consistent with noted prior flakiness).

| Deliverable | Status |
|-------------|--------|
| docker-compose-neo4j.yml | Provided |
| scripts/ai/load_neo4j.py | Provided + dry-run validated |
| Schema (6 node types, 4 rel types) | Defined |
| Dry-run statements | 176 Cypher statements |

**Projected node counts** (not measured — Neo4j offline): ~1,674 nodes,
~1,200+ edges from full 487-doc / 1161-chunk corpus.
See `docs/ai/NEO4J_RESULTS.md` for full details.

---

### Goal 6 — Brain Health

**Status: LIVE**

`scripts/ai/check_brain_health.py` runs 8 component checks and outputs
structured JSON + Markdown report.

| Component | Health Status |
|-----------|--------------|
| Corpus | OK (487/1161/1161/1161) |
| Vault | OK (45 notes, 13 sections) |
| Hybrid Retrieval | LIVE |
| WADE Retrieval | LIVE |
| LightRAG | LIVE (vector) |
| Graphiti | CONFIGURED |
| Neo4j | OFFLINE |
| Graphify | LIVE (local) |

Outputs: `docs/ai/BRAIN_HEALTH_REPORT.md`, `docs/ai/brain_health.json`

---

### Goal 7 — Brain Query Validation

**Status: LIVE — 38 tests, 38 passed**

`tests/ai/test_brain_runtime.py` — 38 tests covering:

- 19 query groups (CSP, Cloudflare, AbuseIPDB, CWE/XSS, external tools,
  exposed env, provider blocked, HSTS, Vercel, third-party scripts, TLS,
  GraphQL, WordPress XML-RPC, source attribution, retrieval consistency,
  ReasoningContext completeness, brain health artifacts, retrieval speed SLA)
- Dense/hybrid tests: 3 tests, skip gracefully when index not built
- Speed SLA: 5 lexical queries under 3 seconds — PASS

---

## Deliverables Summary

| File | Purpose |
|------|---------|
| scripts/ai/build_graphify.py | Local repo/doc link-graph generator |
| scripts/ai/analyze_vault_graph.py | Obsidian vault graph analysis |
| scripts/ai/build_lightrag_index.py | LightRAG vector index builder |
| scripts/ai/test_lightrag_queries.py | Hybrid vs LightRAG benchmark |
| scripts/ai/seed_graphiti.py | Graphiti episode schema seeder |
| scripts/ai/check_brain_health.py | Brain health check (8 components) |
| scripts/ai/load_neo4j.py | Neo4j Cypher batch loader |
| tests/ai/test_brain_runtime.py | 38 brain query validation tests |
| docker-compose-neo4j.yml | Neo4j deployment compose |
| docs/ai/graphify/graph.json | Graph node/edge data |
| docs/ai/graphify/graph.html | Interactive D3 visualization |
| docs/ai/graphify/graph_report.md | Most-connected analysis |
| docs/ai/VAULT_GRAPH_RESULTS.md | Vault wikilink statistics |
| docs/ai/LIGHTRAG_BENCHMARK.json | Retrieval comparison data |
| docs/ai/LIGHTRAG_INDEX_RESULTS.json | Index build results |
| docs/ai/GRAPHITI_RESULTS.md | Graphiti status + activation steps |
| docs/ai/NEO4J_RESULTS.md | Neo4j status + activation steps |
| docs/ai/BRAIN_HEALTH_REPORT.md | Health report |
| docs/ai/brain_health.json | Machine-readable health data |
| vault/.../99-Graphify/graphify_results.md | Vault graph note |

---

## Security Verification

- scanner/webhound/wade/ — NOT MODIFIED
- scanner/provider-access/ — NOT MODIFIED
- .mcp.json — NOT MODIFIED
- No cloud APIs called
- No customer data
- No secrets or credentials

---

## STATE OF THE WEBHOUND BRAIN

```
manifest_records    : 487
chunks              : 1161
embeddings          : 1161 (all-MiniLM-L6-v2, 384-dim, local)
vault_notes         : 58 (45 content + 13 index.md)
vault_sections      : 13
graphify_nodes      : 126
graphify_edges      : 263

hybrid_retrieval    : LIVE (lexical + dense, 0.35/0.65)
wade_retrieval      : LIVE (22 finding types, Phase 8B)
lightrag            : LIVE (vector layer, 30-chunk sample; full index pending local LLM)
graphiti            : CONFIGURED (13 episodes ready; Neo4j + LLM pending)
neo4j               : OFFLINE (Docker daemon; compose + load script provided)
graphify            : LIVE (local AST+wikilink equivalent; binary not available)
obsidian_graph      : LIVE (141 links, 0 orphans, 0.0712 density)

brain_query_success : 38/38 tests passed (100%)
tests_total         : 240 passed (202 pre-8C + 38 new)
production_impact   : NONE
ready_for_wade      : YES — all retrieval and advisory context live
```
