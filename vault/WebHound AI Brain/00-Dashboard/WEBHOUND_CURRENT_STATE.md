---
title: WebHound Current State
phase: CONTROL-1
---
<!-- WEBHOUND-GENERATED -->

# WebHound — Current State (Single Source of Truth)

> Canonical baseline produced by **Phase CONTROL-1** (map/document only — no system changes).
> Full detail: `docs/ai/WEBHOUND_CURRENT_STATE.md` in the repo.

## One-line status

Production scanner + customer-facing **Production WADE** are live and wired. A large **advisory AI/brain layer is built but isolated** — none of it reaches production scoring or customer reports. Main tracking pain = duplication (2× WADE, 3× vault, 4× graph runtimes).

## System map (click through)

- [[02-Scanner Engines/index|Scanner Engines]] · [[07-Scanner/index|Scanner]] — 11 production engine families, ~104 tests
- [[03-WADE/index|Production WADE]] vs [[08-WADE/index|Advisory WADE]] — **two distinct systems sharing a name**
- [[13-Knowledge Corpus/index|Knowledge Library]] — 487 manifests · 1,161 chunks · 1,161 embeddings · hybrid 76% top-1
- [[00-Maps/index|Obsidian Maps]] — **3 vaults exist** (this one + KNOWLEGE VAULT + repo stub); pick one canonical
- [[15-Graphiti/index|Graphiti]] · [[16-Neo4j/index|Neo4j]] · [[14-LightRAG/index|LightRAG]] · [[17-Ollama/index|Ollama]] — **LOCAL-ONLY, not production-wired**
- [[11-External Tools/index|Tool Stack]] — most security tools are knowledge-only; Playwright/httpx/dnspython are production
- MCP Ecosystem — `.mcp.json` = claude-flow only; 5 documented; **0 touch production** (see repo `docs/ai/MCP_MASTER_MATRIX.md`)

## Open PRs

- **#22** Phase 9B-B detection hardening (scanner) — **merge first** (only production-relevant PR)
- #23 Phase 8X tooling audit (docs) · #24 Phase 8Z-A MCP reconciliation (docs) · #2 dependabot (dev)

## Next single move

**Merge PR #22** — finish the validated in-flight scanner hardening; then batch-merge the doc PRs. Do not build new systems.

## CONTROL-2B STATUS — production code ingested into the brain

The brain now sees real WebHound code (746 modules + 820 classes), not just docs/advisory. Brain completeness **~48% → ~74%**.

- Corpus: +746 code-aware chunks (1,907 total); hybrid retrieval now hits production code for 6/8 concepts (`domain_classifier` resolved — was a total blind spot).
- Graphify: 126 → **892 nodes** (382 production); Neo4j: 172 → **2,133 nodes** (+1,961: ScannerEngine/WADEComponent/APIRoute/ThreatIntel/…).
- Graphiti: 26 hallucinated entities removed, 7 production concepts seeded. **Ollama not installed → LLM retrieval still blocked (documented, not faked).**

Reports (repo `docs/ai/`): `PRODUCTION_CODE_INVENTORY.md` · `INDEX_REBUILD_REPORT.md` · `GRAPHIFY_REPAIR_REPORT.md` · `GRAPHITI_REPAIR_REPORT.md` · `PHASE_CONTROL_2B_RESULTS.md`.

## CONTROL-2C CANONICAL BRAIN INDEX STATUS

The code-aware brain is now **canonical and regenerable** from committed manifests — a fresh clone rebuilds the same production-code-aware brain with no local binary blobs.

- Canonical: **5,701 code chunks** (Python + TS/TSX, symbol-level) + 1,161 doc = **6,862 total**; 752 sources included, 42 excluded (lock/env/cache).
- Committed (small/deterministic): `corpus/index/brain_sources_manifest.json`, `corpus/index/code_chunks_manifest.jsonl`, `corpus/index/retrieval_config.json`.
- Regenerated (not committed): `canonical_chunks.jsonl`, `dense/*.npy` (gitignored). Rebuild: `python scripts/ai/build_canonical_brain_index.py [--embed]`.
- Retrieval default now prefers the canonical index (warned fallback, no silent stale doc-only). Traceability: 6 PASS / 3 PARTIAL / 1 FAIL (lexical; all 10 concepts indexed).

Reports (repo `docs/ai/`): `BRAIN_INDEX_ARTIFACT_POLICY.md` · `PHASE_CONTROL_2C_RESULTS.md`. Scripts: `build_canonical_brain_index.py` · `check_brain_traceability.py`. Tests: `tests/ai/test_canonical_brain_index.py`.

**Next single action:** add a committed/CI embedding step (or small embedding shard) so dense retrieval works out-of-the-box on a fresh clone.

## CONTROL-2D DENSE RETRIEVAL STATUS

Dense/hybrid retrieval is now **reproducible from a fresh clone** with no cloud APIs and no hidden local files.

- Build: `build_dense_brain_embeddings.py` (local sentence-transformers; `--dry-run`/`--limit`/`--output-dir`; exits 3 with install hint if the dep is missing — never fakes vectors). Full build = **6,862 × 384** local MiniLM vectors (gitignored).
- Retrieval (`retrieval_config.json` v2): explicit `lexical`/`dense`/`hybrid` modes. Dense present → hybrid; missing → lexical **with warning + rebuild cmd**; never silent/stale. `check_brain_traceability.py` gained `--mode`, `--require-dense`, `--json`.
- **Traceability: lexical 1 PASS / 7 PARTIAL / 2 FAIL → hybrid 9 PASS / 1 PARTIAL / 0 FAIL** (dense fixes scanner orchestrator, threat_intel, production WADE, report rendering). Only `tls_checker` PARTIAL.

Docs (`docs/ai/`): `DENSE_RETRIEVAL_ARTIFACT_POLICY.md` · `BRAIN_DENSE_RETRIEVAL_BUILD.md` · `PHASE_CONTROL_2D_RESULTS.md`. Tests: `tests/ai/test_dense_retrieval_reliability.py`.

**CI gate (added):** a `dense-quality-gate` job (in `.github/workflows/api-tests.yml`) installs sentence-transformers, builds a **concept-seeded** shard (all 10 concept modules + ~1,200-chunk sample), and asserts **≥8/10 concepts found (top-k, rank-robust)** under hybrid — gating dense QUALITY, not just plumbing. The minimal `ai-knowledge` job stays green via contract/fallback tests. `tls_checker` remains PARTIAL on the full index (counted as found; gate has headroom).

**Next single action:** lift `tls_checker` to top-1 on the FULL index (boost code-symbol weighting for exact module-name queries), closing the last PARTIAL.

## CONTROL-2E CODE SYMBOL RANKING STATUS

Exact module/class/function queries now rank real **CODE above generic docs**.

- Ranking logic (`scripts/ai/hybrid_retrieval.py`, no chunk-content change): **code-symbol boost** (+0.25 module-stem / +0.12 symbol match, metadata-driven, generalizes) + **source-priority tie-break** (1 production → 7 planning). `check_brain_traceability.py --show-ranking` added.
- **Full-index hybrid: 9 PASS / 1 PARTIAL → 10 PASS / 0 PARTIAL / 0 FAIL.** `tls_checker` PARTIAL→**PASS** (`tls_checker.py` 1.124 > Nuclei doc 0.858); all 10 top hits are code.
- CONTROL-2D dense-quality-gate re-run: **10/10 found, OK — no regression**. `tests/ai`: 347 passed.

Docs (`docs/ai/`): `RETRIEVAL_RANKING_MODEL.md` · `TRACEABILITY_BENCHMARK.md` · `PHASE_CONTROL_2E_RESULTS.md`. Tests: `tests/ai/test_code_symbol_ranking.py`.

**Knowledge-query guard (added):** the code bias is now gated to symbol-like queries only (`_is_symbol_like_query`), and prose questions demote test chunks (−0.30) + favor docs/knowledge (+0.06). Caught 2 real over-applications (Cloudflare token; HSTS test-file); after the fix **5/5 prose queries rank docs/knowledge #1**, **10/10 code concepts still PASS**, dense-gate 10/10. `tests/ai`: 357 passed.

**Next single action:** tune the boost/penalty constants from a small labeled code-seeking-vs-knowledge query set instead of hand-picked values.

## CONTROL-2F BRAIN REALITY VERIFICATION STATUS

Physically tested whether the brain answers real WebHound questions correctly (read-only, brutally honest).

- **Graphify 90%** (896 nodes, all 10 concepts are real code nodes) · **Obsidian 75%** (dashboard current; deeper notes 8G-generated; 3-vault dup) · **Retrieval reality 6 PASS / 1 PARTIAL / 3 FAIL** (symbol queries 10/10; verbose NL "where is WADE implemented" returns docs) · **end-to-end 4/5 PASS**.
- **Neo4j + Ollama OFFLINE** this phase (WSL containers stopped; not restarted — regenerable via committed loaders). Older vault runtime notes overstate liveness.
- Biggest issue: prose implementation questions surface docs over engine code (inverse of the 2E knowledge guard). Stale/dup: 3 vaults, dual-numbered sections, legacy dense index.

Docs (`docs/ai/`): `OBSIDIAN_REALITY_VERIFICATION.md` · `GRAPHIFY_REALITY_VERIFICATION.md` · `NEO4J_REALITY_VERIFICATION.md` · `RETRIEVAL_REALITY_VERIFICATION.md` · `BRAIN_END_TO_END_TRACES.md` · `BRAIN_STALE_DUPLICATE_REPORT.md` · `BRAIN_REALITY_SCORECARD.md` · `PHASE_CONTROL_2F_RESULTS.md`. Script: `scripts/ai/verify_brain_reality.py`.

**Next single action:** CONTROL-2G — detect code-locating intent ("where is … implemented", "what handles …") so prose implementation questions return engine code, lifting retrieval reality to 9–10/10.

#webhound #dashboard #current-state #baseline #control-2b #control-2c #control-2d #control-2e #control-2f
</content>
