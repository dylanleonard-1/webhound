---
title: Graphify
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 18 — Graphify

→ Existing Phase 8A coverage: [[99-Graphify/Graphify Status|Graphify Status]] · [[08-External Tools/Graphify Status|External Tools Graphify]]

## Status: LIVE (Local Equivalent)

| Metric | Value |
|--------|-------|
| Graphify binary | Not installed (uses local AST + wikilink scanner) |
| Graph nodes | 126 FileNode |
| Graph edges | 263 (34 DEPENDS_ON + 157 WIKI_LINK + others) |
| Export | `docs/ai/graphify/graph.json` |
| HTML viewer | Generated |
| Neo4j loaded | ✅ 126 nodes + 191 rels |

## What Graphify Does

Produces a dependency + relationship graph of the codebase:
- Python `import` analysis → `DEPENDS_ON` edges
- Markdown `[[wikilink]]` → `WIKI_LINK` edges
- Generates `graph.json` consumed by Neo4j loader

## Key Files

- `docs/ai/graphify/graph.json` — 126 FileNode array + edges
- `scripts/ai/load_brain_graph_neo4j.py` — loads graph into Neo4j
- `scripts/ai/graphify_results.md` (Phase 8A)

## Maps Generated

- [[99-Maps/AI Brain Map|AI Brain Map]] · [[99-Maps/Dependency Map|Dependency Map]]

## See Also

- [[16-Neo4j/index|Neo4j]] · [[99-Graphify/index|Phase 8A Graphify]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #graphify #index
