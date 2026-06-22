# Brain Reality Scorecard — Phase CONTROL-2F

Each layer scored 0–100 on Accuracy / Completeness / Usefulness / Freshness /
Trustworthiness, with an overall. Evidence in the companion `*_REALITY_*` docs.

| Layer | Acc | Compl | Useful | Fresh | Trust | Overall | Notes |
|-------|----:|------:|-------:|------:|------:|--------:|-------|
| **Corpus hybrid retrieval** | 90 | 85 | 90 | 90 | 90 | **89** | 1,161 doc + 5.7k code chunks; offline; provenance-stamped |
| **Dense retrieval** | 90 | 85 | 90 | 85 | 85 | **87** | 6,886 vectors local MiniLM; regenerable; gated ≥8/10 in CI |
| **Canonical index** | 95 | 90 | 90 | 90 | 90 | **91** | deterministic manifests; fresh-clone rebuildable |
| **Graphify / local graph** | 90 | 80 | 85 | 90 | 90 | **87** | 896 nodes, all 10 concepts real code; module-level only |
| **Obsidian** | 80 | 80 | 80 | 65 | 70 | **75** | dashboard current; deeper notes 8G-generated; 3-vault dup |
| **Retrieval (NL question answering)** | 70 | 70 | 70 | 85 | 75 | **70** | symbol queries 10/10; prose impl. questions 6/10 |
| **Neo4j** | – | – | – | 20 | 30 | **35** | OFFLINE this phase; regenerable; last-known 2,133 nodes |
| **Graphiti** | 30 | 30 | 25 | 20 | 25 | **26** | OFFLINE; entity layer historically hallucinated (phi3) |
| **LightRAG** | 30 | 25 | 25 | 30 | 30 | **28** | 52-chunk experiment; corpus hybrid is the real retrieval |

## Overall brain reality
- **Strong & trustworthy:** canonical index (91), corpus hybrid (89), dense (87),
  Graphify (87) — the code-aware retrieval/graph layer is real and reproducible.
- **Good with caveats:** Obsidian (75) — accurate dashboard, generated deeper notes.
- **Weak / offline:** NL-question retrieval for verbose implementation questions (70),
  and the entire graph-DB tier (Neo4j 35, Graphiti 26, LightRAG 28) which is offline
  and/or experimental.

**Composite (committed/reproducible layers, excluding offline DB tier): ~83%.**
**Composite (all layers incl. offline DB tier): ~65%.**
