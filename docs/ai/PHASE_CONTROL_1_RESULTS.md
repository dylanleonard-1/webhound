# Phase CONTROL-1 — System Baseline & Linkage Map: Results

**Type:** MAP / DOCUMENT ONLY. No features, installs, MCP/`.mcp.json` edits, scanner/WADE/production/billing/auth/provider-access changes, or deploys. No secrets/customer data. **Not merged** (PR opened).
**Branch:** `feat/control-1-system-baseline-linkage-map` off `main` @ `6035da9`. **Date:** 2026-06-17.
**Primary deliverable:** [`WEBHOUND_CURRENT_STATE.md`](WEBHOUND_CURRENT_STATE.md) (15 sections + GOAL traces). **Vault mirror:** one note at `vault/WebHound AI Brain/00-Dashboard/WEBHOUND_CURRENT_STATE.md`.

---

## What was audited

Production scan flow (frontend→API→worker→orchestrator→engines→WADE→findings→DB→reports), production vs advisory WADE, the advisory AI layer (corpus/embeddings/retrieval/LightRAG/Neo4j/Graphiti/Ollama/`scripts/wade/reasoning/`), knowledge library, 3 Obsidian vaults, graph/runtime liveness (snapshots), MCP state, security-tool integration state, duplicate/confusion map, and all open PRs. Evidence reused from 8X/9A/9B-A/9B-B/8Z-A + fresh read-only verification (3 parallel Explore passes + direct reads).

## What was NOT changed

`.mcp.json` (unchanged), scanner code, WADE scoring, provider-access, billing, auth, any production/runtime code. No installs, no deploys, no external calls, no live runtime probes, no secrets, no customer data. No vault bulk-update (exactly **one** new generated note). Stray `apps/web/package-lock.json` not staged.

## Key findings

1. **Production core is healthy and wired:** 11 engine families + Production WADE run on every scan; `Scanner._run_wade()` confirmed at `orchestrator.py` L1964/called L728; WADE is customer-facing (`wade-summary.tsx`, `json_report._wade_section`). ~104 scanner + ~76 api test files.
2. **The advisory layer is fully isolated:** import scan of `scanner/**` and `apps/api/**` for corpus/lightrag/neo4j/graphiti/retrieval/`scripts.wade.reasoning` = **zero matches**. **No advisory output reaches production scoring or reports.** `ai_summary.py` (Claude, opt-in) takes only structured findings.
3. **Two "WADE":** production `scanner/webhound/wade/` vs advisory `scripts/wade/reasoning/` (all `advisory_only=True`, `production_unchanged=True`). Naming collision is the #1 confusion source.
4. **Dormant/stub systems mislabel-able as live:** `wade_correlation.analyse_website` (tests, no call site) and `worker/report_tasks.generate_report` (stub).
5. **Runtimes look connected but aren't:** Neo4j/Graphiti/LightRAG/Ollama recorded LIVE (2026-06-14) but local-only, zero production imports. LightRAG graph extraction is a stub (vector-only).
6. **MCP:** 1 live (claude-flow), 5 documented, 0 production-touching.

## Current-state summary

Numbers: 11 production engines · ~180 test files · 487 manifests / 1,161 chunks / 1,161 embeddings · hybrid retrieval 76% top-1 · 3 Obsidian vaults (8 / 132 / 114 notes) · 4 local runtimes · 1 live MCP. **Completeness of the *product*: high and tested. Coherence of the *project*: hurt by duplication, not by missing function.**

## Duplicate / confusion summary

2× WADE (name) · 3× Obsidian vault (one typo'd "KNOWLEGE", two heavily overlapping) · 4× graph/runtime systems that look production-wired but are local-only · duplicate vault section numbers · knowledge mirrored across `knowledge/` + corpus + 2 vaults · dormant correlation service + stub report task that read as live. **All flagged DO-NOT-DELETE-unless-approved** (see GOAL 11).

## Open-PR summary

- **#22** 9B-B detection hardening — production scanner, tested, CI green — **MERGE FIRST**.
- #23 8X tooling audit (docs), #24 8Z-A MCP reconciliation (docs), this CONTROL-1 PR (docs) — zero-risk, **batch-merge after #22**.
- #2 dependabot esbuild — dev dependency, review/merge.

## The next single move

**MERGE PR #22 (Phase 9B-B Detection Hardening).** It is the only open PR that improves the production product, it is already validated + CI-green, and merging it finishes in-flight core work instead of starting anything new — the exact posture this phase set out to enforce. Everything else (doc PR batch-merge, 8Z-B, vault consolidation, 9C) waits until #22 lands.

---

*Audit complete. Only documentation/mapping changed: `docs/ai/WEBHOUND_CURRENT_STATE.md`, `docs/ai/PHASE_CONTROL_1_RESULTS.md`, and one vault note.*
</content>
