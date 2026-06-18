# Phase CONTROL-2B — Production Code Brain Ingestion: Results

**Type:** KNOWLEDGE-INGESTION. No scanner/WADE/production/`.mcp.json`/billing/auth/provider-access changes; no installs; no deploys. Committed diff = new scripts + new docs + one vault-dashboard update. Indexes/Neo4j/LightRAG data are local build artifacts (not committed).
**Branch:** `feat/control-2b-production-code-ingestion` off `main` @ `ace3fab`.
**Precheck:** main clean; PR #29 (2A verification) OPEN; Neo4j ✅ up; **Ollama ❌ not installed**; corpus + hybrid index present.

## Neo4j production ingestion (Goal 5) — before → after

| Metric | Before | After | Δ |
|--------|------:|------:|---|
| Nodes | 172 | **2,133** | +1,961 |
| Relationships | 224 | **3,386** | +3,162 |

New labels loaded: `CodeModule` (746) + `CodeClass` (820), tagged with category labels `ScannerEngine` (44), `WADEComponent` (13), `APIRoute` (25), `APIService` (55), `APIModel` (34), `ThreatIntel` (20), `ProviderRule` (16), `ReportComponent` (19), `ScannerCore` (26), `Frontend` (168), `TestModule` (179) + `IMPORTS`/`DEFINES` edges. (395 import-target stubs have no category — external/package paths.)

## LightRAG (Goal 7) — honest status

The old `lightrag_storage/` is a **52-chunk experiment with a broken graph (1 relationship)** and is **retired in favor of the rebuilt code-aware hybrid index** (1,907 chunks). A full LightRAG **graph-mode** rebuild requires Ollama (LLM extraction) which is **not installed** → **not performed, not faked**. The working retrieval path is the corpus hybrid index (`dense_with_code/`, 1,907 chunks, all-MiniLM, no Ollama). LightRAG vector-only rebuild was deemed redundant with that index.

## Traceability (Goal 8) — 8 concepts × 7 layers

| Concept | Corpus | Hybrid | Obsidian | Graphify | Neo4j | Graphiti | LightRAG |
|---------|--------|--------|----------|----------|-------|----------|----------|
| cookie_scanner | PASS | PASS | PASS | PASS | PASS | PASS | PARTIAL |
| domain_classifier | PASS | PASS | FAIL | PASS | PASS | PASS | FAIL |
| tls_checker | PASS | PASS | PASS | PASS | PASS | PASS | PARTIAL |
| threat_intel | PASS | PASS | PASS | PASS | PASS | PASS | PARTIAL |
| WADE | PASS | PARTIAL | PASS | PASS | PASS | PASS | FAIL |
| Scanner Orchestrator | PASS | PASS | FAIL | PASS | PASS | PASS | PARTIAL |
| Verification Flow | PASS | PARTIAL | PASS | PASS | PASS | PARTIAL | PARTIAL |
| API Authentication | PASS | PASS | PASS | PASS | PASS | PARTIAL | PARTIAL |

vs CONTROL-2A where `domain_classifier` was **FAIL on all 7 layers**; it is now PASS on 5 (Corpus/Hybrid/Graphify/Neo4j/Graphiti).

## Brain linkage score matrix (Goal 9)

| Layer | Exists | Operational | Contains Prod Code | Retrievable | Linked |
|-------|:---:|:---:|:---:|:---:|:---:|
| Corpus | ✅ | ✅ | ✅ (746 chunks) | ✅ | ✅ |
| Hybrid Retrieval | ✅ | ✅ | ✅ (1907 idx) | ✅ (6/8 code top-1) | ✅ |
| Obsidian | ✅ | ✅ | ⚠️ topics only | ⚠️ manual | ⚠️ |
| Graphify | ✅ | ✅ | ✅ (382 prod nodes) | ✅ (json) | ✅ |
| Neo4j | ✅ | ✅ | ✅ (1566 prod) | ✅ (Cypher) | ✅ |
| Graphiti | ✅ | ⚠️ (no LLM) | ✅ (7 concepts) | ⚠️ structural only | ✅ |
| LightRAG | ⚠️ retired | ❌ | ❌ | ❌ | ❌ |

## Before → After scores

| Layer | 2A | 2B |
|-------|---:|---:|
| Obsidian | 70% | 70% (unchanged — topic mirror) |
| Graphify | 35% | **80%** |
| Neo4j | 40% | **80%** |
| Graphiti | 30% | **55%** (cleaned + concepts; LLM still blocked) |
| LightRAG | 25% | 20% (retired; superseded by hybrid index) |
| Corpus + Hybrid retrieval | 85% | **92%** (now code-aware) |
| **Overall Brain Completeness** | **~48%** | **~74%** |

## Gap analysis (Goal 10 — nothing hidden)

| Gap | Severity | Note |
|-----|----------|------|
| Ollama not installed → Graphiti/LightRAG LLM retrieval blocked | **HIGH** | structural memory works; semantic retrieval does not |
| `apps/web` (TS, 168 modules) absent from Graphify | **MEDIUM** | Python-AST builder; covered in corpus + entities json |
| Obsidian misses `domain_classifier` / `orchestrator` by name | **MEDIUM** | topic mirror not regenerated (no bulk vault edits this phase) |
| Code-augmented index not committed (build artifact) | **MEDIUM** | reproducible via scripts; committed index still doc-only |
| "Verification Flow" weak in hybrid/Graphiti | **LOW** | concept spans multiple API modules; not a single hit |
| 1 low-quality Graphiti entity retained | **LOW** | kept conservatively to avoid over-deletion |
| LightRAG retired but files remain | **LOW** | superseded; left in place, documented |

## STATE OF THE BRAIN

1. **Does the brain now see production code?** **Yes.** 746 modules + 820 classes are in the corpus (code-aware chunks), the hybrid index (1,907), Graphify (382 prod nodes), and Neo4j (1,961 new nodes). The 2A CRITICAL "production invisible" gap is closed across 4 of 7 layers.
2. **Can every major scanner engine be traced?** **Yes** — cookie_scanner, tls_checker, threat_intel, domain_classifier all PASS on Corpus/Hybrid/Graphify/Neo4j (engines category = 44 modules).
3. **WADE?** **Yes** — production WADE (13 modules) in corpus/graph/Neo4j; retrievable (doc-first for the bare term "WADE", code for components).
4. **API routes?** **Yes** — 25 routers + 55 services + 34 models in corpus/graph/Neo4j; API Authentication retrieves `apps/api/schemas/auth.py`.
5. **Reports?** **Yes** — 19 reporting modules ingested (ReportComponent label in Neo4j, corpus chunks).
6. **Biggest remaining weakness:** **the LLM tier (Ollama) is uninstalled**, so Graphiti/LightRAG semantic retrieval is structural-only — and the code-aware index is a local artifact (the *committed* corpus index is still doc-only). Obsidian remains a topic mirror, and frontend TS isn't in Graphify.
7. **Next single action:** **Promote the code-aware hybrid index to the committed/default retrieval path** (wire `hybrid_retrieval.py` to the 1,907-chunk index and commit the regenerable chunk manifest) so "the brain sees code" persists beyond this local build — *or*, if the LLM tier matters, install Ollama to unblock Graphiti/LightRAG. Recommended: the former (cheap, high-value, no new dependency).

*Ingestion complete. No production code, scanner, WADE, `.mcp.json`, billing, auth, or provider-access modified; no installs; no deploys.*
</content>
