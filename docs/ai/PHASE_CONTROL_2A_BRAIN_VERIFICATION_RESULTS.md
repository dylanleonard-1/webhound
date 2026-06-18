# Phase CONTROL-2A — Brain & Graph Verification: Results

**Type:** VERIFICATION-ONLY. No installs, no production/scanner/WADE/`.mcp.json`/billing/auth/provider changes, no deploys. Docs-only.
**Branch:** `feat/control-2a-brain-verification` off `main` @ `ace3fab`.
**Precheck:** main current (`ace3fab`); open PRs **#24** (8Z-A MCP), **#2** (dependabot) — both untouched; `docs/ai/WEBHOUND_CURRENT_STATE.md` present. Live status: **Neo4j ✅ up**, **Ollama ❌ down**, Graphiti (data in Neo4j, retrieval offline), LightRAG (static 52-chunk store), corpus hybrid index ✅.
**Companion docs:** OBSIDIAN / GRAPHIFY / NEO4J / GRAPHITI / LIGHTRAG / OLLAMA `_VERIFICATION.md`, `KNOWLEDGE_TRACE_TESTS.md`, `BRAIN_LINKAGE_MATRIX.md`.

## Scores

| Layer | Score | One-line |
|-------|------:|----------|
| Obsidian | **70%** | broad topical mirror; 3-vault dup; no code/runtime link |
| Graphify | **35%** | local-equiv only; 126 nodes; **0 production coverage** |
| Neo4j | **40%** | live, 172 nodes, but only file-graph + Graphiti; no corpus/product entities |
| Graphiti | **30%** | 19 good episodes, **27 garbage entities**, retrieval offline (Ollama down) |
| LightRAG | **25%** | 52-chunk subset, graph broken (1 relationship) |
| Ollama | **0% operational** | down; only the graph experiments depend on it |
| Knowledge corpus + hybrid retrieval *(the real brain)* | **85%** | 1161 chunks, 76% top-1, offline, provenance-stamped |
| Knowledge-trace (5 concepts) | **40%** | strong in corpus/knowledge/Obsidian; near-zero in graph stack; 1 blind spot |

### Overall Brain Completeness: **~48%**
Weighted: the **knowledge corpus + hybrid retrieval + Obsidian docs are real and strong**; the **graph/LLM tier (Graphify/Neo4j/Graphiti/LightRAG/Ollama) is largely isolated, thin, or non-functional**, and **no brain layer sees production code**.

## Gap analysis (classified)

| Gap | Severity | Detail |
|-----|----------|--------|
| Production code invisible to all graph layers | **CRITICAL** | Graphify/Neo4j/Graphiti/LightRAG cover `scripts/`+vault only; `scanner/webhound/`, `apps/api/` = 0 nodes |
| `domain_classifier` absent from every layer | **HIGH** | real prod module, FAIL on all 7 layers (KNOWLEDGE_TRACE) |
| Graphiti entity extraction = hallucinated garbage | **HIGH** | phi3:mini produced noise; entity graph unusable |
| LightRAG is a 52-chunk experiment w/ broken graph | **HIGH** | conflated with the real 1161-chunk corpus index |
| No concept→production-module mapping | **HIGH** | exact module names score 0 in corpus/knowledge/vault |
| Ollama down | **MEDIUM** | blocks Graphiti/LightRAG only; not production/retrieval-critical |
| Three Obsidian vaults (one typo'd) | **MEDIUM** | duplication; no single canonical vault |
| Neo4j corpus-loader never run | **MEDIUM** | `load_neo4j.py` labels absent; graph is thin |
| Duplicate Graphiti episodes | **LOW** | re-seeding produced dupes (19 rows ≈ 13 unique) |
| Isolated systems (entire advisory brain) | **LOW→MEDIUM** | built, runnable, but not wired to production (by design, per CONTROL-1) |

## STATE OF THE WEBHOUND BRAIN

1. **Does Obsidian see the entire system?** Topically ~70% yes (every area has a note), but as a **generated mirror** — no code or runtime linkage, and split across 3 vaults.
2. **Does Graphify?** **No.** It's a local-equiv graph of `scripts/`+vault (126 nodes) with **zero production-code coverage**.
3. **Does Neo4j represent it?** **Partially (40%)** — live but only a 126-node file graph + a small Graphiti memory store; no corpus/scanner/provider/threat entities.
4. **Does Graphiti retrieve useful knowledge?** **No (today).** 13 genuine seed episodes exist, but entities are hallucinated garbage and retrieval is offline (Ollama down).
5. **Does LightRAG?** **No** — 52-chunk sample with a failed graph (1 relationship). The *corpus hybrid index* (separate) is the real, working retrieval (85%).
6. **Can the same concept be found from every layer?** **No.** No concept is PASS on all layers; `domain_classifier` is FAIL on every layer; the graph stack is unreliable for all 5 tested concepts.
7. **Biggest missing link:** **The production product (scanner engines, production WADE, API) is invisible to every graph/memory layer** — the brain maps its own advisory scripts and docs, not WebHound. (Closely followed by: the graph/LLM tier is non-functional — Graphiti garbage entities + Ollama down + LightRAG 52-chunk.)
8. **Next single action:** **Treat the corpus hybrid index + Obsidian as the canonical brain; point graph/knowledge ingestion at production code (`scanner/webhound/` + `apps/api/`) so concepts like `cookie_scanner`/`domain_classifier` map to real modules.** Do **not** invest further in the Graphiti/LightRAG/Ollama graph tier until extraction uses a competent model — or formally deprecate it. (One move: extend `build_graphify.py` / corpus ingestion to include `scanner/webhound/`, closing the CRITICAL gap; everything else waits.)

*Verification complete. No services started, nothing installed, no production code touched.*
</content>
