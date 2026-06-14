---
title: Graphify Results — Phase 8C
description: Link-graph analysis of WebHound Brain scripts, tests, and vault notes
tags: [graphify, graph-analysis, phase-8c, repo-map]
created: 2026-06-14
---
<!-- WEBHOUND-GENERATED -->

# Graphify Results — Phase 8C

> Graphify binary is not available in this environment.
> A local equivalent (AST import scanner + wikilink extractor) was used.
> See: [[build_graphify.py]] → `docs/ai/graphify/graph.html`

## Graph Statistics

| Metric | Value |
|--------|-------|
| Total nodes | 126 |
| Total edges | 263 |
| Python files | 20 |
| Markdown files | 106 |
| Orphan nodes | 0 |

## Most Referenced Files (in-degree)

| File | In-links |
|------|---------|
| hybrid_retrieval.py | 26 |
| retrieval_service.py | 17 |
| context_builder.py | 16 |
| WADE Overview.md | 13 |
| provider_resolver.py | 12 |
| taxonomy_resolver.py | 11 |
| false_positive_resolver.py | 11 |
| Corpus Overview.md | 11 |

## Most Referencing Files (out-degree)

| File | Out-links |
|------|-----------|
| test_wade_retrieval.py | 62 |
| test_hybrid_retrieval.py | 12 |
| WebHound Master Map.md | 8 |
| wade/__init__.py | 6 |
| AI Brain Map.md | 6 |

## Key Observations

- [[hybrid_retrieval.py]] is the most-referenced file (26 in-links) — central to all retrieval
- [[WADE Overview]] is the most-referenced vault note (13 in-links) — knowledge hub
- All 126 nodes are connected — zero orphans
- See [[docs/ai/graphify/graph.html]] for interactive D3 visualization

## See Also

- [[Corpus Overview]] — knowledge base structure
- [[WADE Intelligence Map]] — WADE retrieval relationships
- [[AI Brain Map]] — overall brain architecture
