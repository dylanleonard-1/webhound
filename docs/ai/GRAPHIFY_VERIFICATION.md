# Graphify Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only). No installs.

## Is "Graphify" a real installed tool? — NO

`docs/ai/GRAPHIFY_SETUP.md` states verbatim: *"Graphify is not currently installed in this environment."* The real `graphify-python` package is **not installed**. What exists instead is a **WebHound-built local equivalent**:
- `scripts/ai/build_graphify.py` — AST import-scan (Python) + wikilink extraction (Markdown).
- Output: `docs/ai/graphify/graph.json`, `graph.html`, `graph_report.md`.

So "Graphify" here = a static, self-built file-relationship graph, **not** an interactive Graphify tool. (This same 126-node graph is what `load_brain_graph_neo4j.py` pushes into Neo4j as `FileNode` — see NEO4J_VERIFICATION.md.)

## Graph statistics (from `graph.json` / `graph_report.md`)

| Metric | Value |
|--------|------:|
| Total nodes | **126** |
| Total edges | **263** |
| Python files | 20 |
| Markdown files | 106 |
| Orphan nodes | 0 |

**Node coverage by top-level dir:** `vault` 58 · `md` 45 · `scripts` 15 · `tests` 5 · `docs` 3 · **`scanner/webhound` 0 · `apps/api` 0 · `worker` 0**.

## Representation check (what's in the graph vs missing)

| Subsystem | In Graphify graph? |
|-----------|--------------------|
| Advisory WADE (`scripts/wade/`) | ✅ (top in/out-degree: retrieval_service, context_builder, resolvers) |
| Hybrid retrieval (`scripts/ai/hybrid_retrieval.py`) | ✅ (highest in-degree, 26) |
| Knowledge corpus (Overview notes, chunk/manifest refs) | ✅ (via Markdown wikilinks) |
| Obsidian notes | ✅ (58 vault nodes) |
| AI brain tests (`tests/ai/`) | ✅ (5) |
| **Production scanner (`scanner/webhound/`, all engines)** | ❌ **0 nodes** |
| **Production WADE (`scanner/webhound/wade/`)** | ❌ 0 (only advisory `scripts/wade/`) |
| **API / apps (`apps/api/`)** | ❌ 0 |
| Neo4j / Graphiti / LightRAG / Ollama (as runtime nodes) | ❌ only as Markdown status notes, not graph entities |
| Reports / infrastructure (code) | ❌ |

## What's missing from the graph

**The entire production product.** Graphify scans only `scripts/` (advisory brain) + `vault/`/`docs/` Markdown. The actual scanner engines, production WADE, API, and worker — the thing customers use — have **zero** graph representation. The graph is a map of the *advisory/knowledge layer talking to itself*, not of WebHound.

**Score: 35% (D)** — functional as a script/doc-link graph, but blind to 100% of production code.
</content>
