# Brain Stale / Duplicate Report — Phase CONTROL-2F

Report-only (no deletions). Issues that could mislead a reader or agent.

## Stale / overstated
| Item | Issue | Severity |
|------|-------|----------|
| Vault graph-runtime notes (`14 LightRAG`, `15 Graphiti`, `16 Neo4j`, `17 Ollama`) | Describe local runtimes as LIVE; **Neo4j + Ollama are currently OFFLINE** | MEDIUM |
| Phase-8G engine/WADE notes (`02/07 Scanner`, `03/08 WADE`) | Generated at Phase 8G; architecturally correct but predate CONTROL-2x; no per-module code links | LOW |
| CONTROL-2A `GRAPHITI_VERIFICATION.md` "27 garbage entities" | Those entities lived in the now-stopped Neo4j container — historical, not current | LOW |

## Duplicate
| Item | Issue | Severity |
|------|-------|----------|
| **Three vaults** (`vault/webhound`, `vault/WebHound AI Brain`, `vault/WEBHOUND KNOWLEGE VAULT`) | No single canonical vault; KNOWLEGE VAULT has a typo'd name | MEDIUM |
| Dual-numbered AI-Brain sections (`03`&`08` WADE, `04`&`13` Corpus, `06`&`09` Threat Intel, `08`&`11` External Tools) | Two numbering schemes coexist | LOW |
| Two retrieval indexes (`corpus/indexes/dense` doc-only vs `corpus/index/` canonical) | Legacy 7A doc index still committed alongside the canonical index | LOW |

## Wrong graph nodes / hallucinated entities
| Item | Issue | Severity |
|------|-------|----------|
| Graphiti `Entity` nodes (offline) | Were hallucinated junk (phi3:mini) per CONTROL-2A; not currently loaded | MEDIUM (if Neo4j is rebuilt, re-run the CONTROL-2B entity cleanup) |

## Docs contradicting current code / dead links
- None found contradicting current code. The dashboard (`WEBHOUND_CURRENT_STATE.md`) is
  current. No broken intra-doc links detected among the CONTROL-2x reports.
- Note: `RETRIEVAL_REALITY_VERIFICATION.md` records that prose "where is WADE implemented"
  returns docs — a *ranking* gap, not a stale-doc contradiction.

## Recommended (NOT executed — report only)
1. Pick ONE canonical vault; mark the other two deprecated.
2. Add a freshness/“generated Phase 8G” banner + "runtime status is point-in-time" note
   to the graph-runtime vault notes.
3. Consider retiring the legacy `corpus/indexes/dense` once canonical dense is the sole path.
**Do not delete anything without owner approval.**
