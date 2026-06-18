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

#webhound #dashboard #current-state #baseline #control-2b #control-2c
</content>
