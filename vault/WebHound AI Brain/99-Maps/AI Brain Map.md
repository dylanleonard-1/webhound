---
title: AI Brain Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# AI Brain Map (Phase 8G)

Updated AI Brain component map. See also [[00-Maps/AI Brain Map|Phase 8A AI Brain Map]].

```
                    ┌──────────────────────────────┐
                    │       KNOWLEDGE CORPUS        │
                    │  487 records · 1161 chunks    │
                    │  manifest.jsonl (JSONL)        │
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┼───────────────────────┐
              ▼                    ▼                       ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │   HYBRID         │  │    LightRAG       │  │    GRAPHITI       │
   │   RETRIEVAL      │  │   LIVE_FULL       │  │     LIVE          │
   │  lexical+vector  │  │  19 entities      │  │  13 episodes      │
   │  1161 chunks     │  │  phi3:mini LLM    │  │  27 Entity nodes  │
   └────────┬─────────┘  └───────┬──────────┘  └───────┬──────────┘
            │                    │                      │
            └────────────────────┼──────────────────────┘
                                 │
                         ┌───────▼───────┐
                         │    NEO4J       │
                         │  172 nodes     │
                         │  191 rels      │
                         │  FileNode+Epis │
                         └───────┬───────┘
                                 │
                    ┌────────────▼─────────────┐
                    │       WADE LAYER          │
                    │  query → retrieve → enrich│
                    │  22 finding types covered │
                    └────────────┬─────────────┘
                                 │
                         ┌───────▼───────┐
                         │   SCANNER      │
                         │ 14 modules     │
                         └───────────────┘
```

## Component Links

- [[13-Knowledge Corpus/index|Corpus]] · [[14-LightRAG/index|LightRAG]] · [[15-Graphiti/index|Graphiti]]
- [[16-Neo4j/index|Neo4j]] · [[17-Ollama/index|Ollama]] · [[08-WADE/index|WADE]]

#webhound #maps #ai-brain
