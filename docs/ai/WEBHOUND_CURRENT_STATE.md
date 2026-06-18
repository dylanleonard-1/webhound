# WebHound — Current State (Single Source of Truth)

**Phase:** CONTROL-1 — System Baseline & Linkage Map. **MAP / DOCUMENT ONLY.** No features, installs, MCP/`.mcp.json`, scanner/WADE/production/billing/auth/provider-access changes, or deploys. Evidence reuses Phase 8X (PR #23), 9A (merged), 9B-A (merged), 9B-B (PR #22), 8Z-A (PR #24) + fresh read-only verification.
**Branch:** `feat/control-1-system-baseline-linkage-map` off `main` @ `6035da9`. **Date:** 2026-06-17.
**Evidence convention:** every path/function below was confirmed by direct read-only inspection on this branch. Runtime liveness is from snapshot JSONs dated 2026-06-14 (no live calls made in this audit). Anything unconfirmed is marked **UNVERIFIED**.

---

## 1. Executive summary

WebHound is a **production website-security scanner** (FastAPI + Celery + a Python `webhound` scanner package + Next.js web) with a **real, customer-facing WADE drift/anomaly layer wired into every scan**. Around that core, a **large advisory AI/knowledge/brain layer** was built (corpus, embeddings, hybrid retrieval, LightRAG, Neo4j, Graphiti, Ollama, a `scripts/wade/reasoning/` shadow engine, and 3 Obsidian vaults). **The advisory layer is structurally isolated: zero of it reaches the production scanner scoring or customer reports** (verified by import scan). The MCP ecosystem is minimal (1 live server, `claude-flow`; 5 documented). The biggest *tracking* problems are duplication: **three Obsidian vaults**, **two things both called "WADE"** (production vs advisory), and **multiple graph/runtime systems** that look production-connected but are local-only. **Recommendation: stop adding systems; finish the one in-flight production improvement (PR #22) and consolidate the duplicates — do not build more.**

---

## 2. Current architecture map

```
CUSTOMER
  │
  ▼
FRONTEND  apps/web (Next.js)
  scan/page.tsx ──POST /public/scan──┐   dashboard/scans ──POST /scan-jobs──┐
  │                                   ▼                                       ▼
API  apps/api (FastAPI)   routers/public_scan.py            routers/scan_jobs.py
  │                                   └──────── Celery: run_scan.delay() ─────┘
  ▼
WORKER  worker/scan_tasks.py ──► ORCHESTRATOR  scanner/webhound/core/orchestrator.py (class Scanner.scan())
  │                                   │
  │   target/page/browser/tls-dns engines ─► engines/ (11 families)
  │   ► _run_wade()  ◄── PRODUCTION WADE  scanner/webhound/wade/   (baseline→diff→anomaly→classify→timeline)
  │   ► dedup / FP-filter / correlation / risk-scoring / advisor / security-graph
  ▼
FINDINGS  models/finding.py FindingRecord  + grouped_finding.py
  ▼
DB (Postgres, 42 Alembic migrations)  scan_results / findings / grouped_findings / baselines / reports
  ▼
REPORTS  scanner/webhound/reporting/{json,pdf,markdown,csv,sarif} ──► apps/web results/[id] (WADESummary, GroupedFindingsTable)

╔═══════════ ADVISORY LAYER (built, NOT wired to the above) ═══════════╗
║ corpus/ (1161 chunks, 1161 embeddings) → scripts/ai/hybrid_retrieval.py
║   → LightRAG (vector-only stub) · Neo4j (local) · Graphiti (local) · Ollama (local)
║   → scripts/wade/reasoning/ (attack-chain/root-cause/priority/executive; advisory_only=True)
║   → 3 Obsidian vaults (knowledge mirror)        [reaches reports: NO]
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 3. Scanner state

See **§GOAL 4** below. Summary: 11 production-active engine families, all wired in the orchestrator, ~104 scanner test files. 9A audit MERGED, 9B-A coverage MERGED, **9B-B hardening OPEN (PR #22)**.

## 4. WADE state

See **§GOAL 5**. Two distinct systems both named "WADE": **Production WADE** (`scanner/webhound/wade/`, customer-facing, wired) and **Advisory WADE** (`scripts/wade/reasoning/`, shadow-only, not wired). Plus a **dormant** cross-scan correlation service (`apps/api/services/wade_correlation.py`).

## 5. Knowledge library state

See **§GOAL 6**. 487 manifest records, 1,161 chunks, 1,161 embeddings (all-MiniLM-L6-v2, 384-dim), hybrid retrieval 76% top-1. Local-only; advisory.

## 6. Obsidian state

See **§GOAL 7**. **Three vaults** (`vault/webhound` 8 notes stub; `vault/WebHound AI Brain` 132 notes generated; `vault/WEBHOUND KNOWLEGE VAULT` 114 notes generated). Two generated vaults overlap heavily. Local-only; not customer-facing.

## 7. Graph/runtime state

See **§GOAL 8**. Neo4j / Graphiti / LightRAG / Ollama recorded **LIVE (local) on 2026-06-14**. None imported by production or apps/api code. Local-only.

## 8. MCP state

See **§GOAL 9**. `.mcp.json` = `claude-flow` only. 5 documented MCPs. **0 MCPs touch production.** PR #24 (8Z-A) reconciles the full ecosystem.

## 9. Tooling state

See **§GOAL 10**. Most security tools (Nuclei/ZAP/sqlmap/Semgrep/Gitleaks/…) are **knowledge-only** (ingested docs). Production-integrated: Playwright (opt-in), Python `httpx`, `dnspython`.

## 10. Production path

See **§GOAL 2**. Customer → web → API → Celery → orchestrator → engines → Production WADE → findings → DB → reports → web. Fully active.

## 11. Advisory path

See **§GOAL 3**. corpus → embeddings → hybrid retrieval → LightRAG/Neo4j/Graphiti/Ollama → `scripts/wade/reasoning/` → advisory outputs. **Reaches reports: NO.**

## 12. Isolated systems

Built and runnable but **not wired into production**: entire advisory layer (corpus/retrieval/LightRAG/Neo4j/Graphiti/Ollama/`scripts/wade/reasoning/`), all 3 Obsidian vaults, all documented MCPs, the `wade_correlation.analyse_website` cross-scan service (has tests, no call site), `worker/report_tasks.generate_report` (stub).

## 13. Duplicate/confusing systems

See **§GOAL 11**. Headlines: 2× "WADE", 3× Obsidian vault, 4× graph/runtime systems, duplicate numbered vault sections, knowledge mirrored in `knowledge/` + corpus + 2 vaults.

## 14. Open PR status

See **§GOAL 13**. Open: #22 (9B-B scanner hardening — product), #23 (8X audit — docs), #24 (8Z-A MCP — docs), #2 (dependabot esbuild — dev dep).

## 15. Immediate next recommendation

See **§GOAL 14**: **Merge PR #22 (Phase 9B-B detection hardening)** — the single highest-value, fully-validated, production-relevant move; then consolidate, do not build new.

---

# GOAL 2 — Production Flow Trace ("What customers actually see")

| # | Step | Repo path | Function/class | Evidence | Active prod? | Tested? | Linked to Obsidian? |
|---|------|-----------|----------------|----------|:---:|:---:|:---:|
| 1 | Frontend submit | `apps/web/src/app/scan/page.tsx` (+ `dashboard/scans`) | `ScanEntryPage` | `POST /public/scan {url}` → redirect to status | ✅ | ⚠ no component test | mirror-only |
| 2 | API accept | `apps/api/routers/public_scan.py`, `routers/scan_jobs.py` | `create_scan_job` | `run_scan.delay(job.id, url, profile)` | ✅ | ✅ `test_scan_jobs.py`, `test_public_scan.py` | no |
| 3 | Worker→Orchestrator | `worker/scan_tasks.py` → `scanner/webhound/core/orchestrator.py` | `Scanner.scan()` (L448) | drives target/crawl/page/browser/tls-dns + WADE | ✅ | ✅ `test_orchestrator.py` | mirror-only |
| 4 | Engines | `scanner/webhound/engines/` | 11 families (headers, cookies, javascript, secrets, forms, recon, compromise, cms, api_discovery, threat_intel, tls_dns) | each wrapped by `_safe()` w/ timeout+diagnostics | ✅ all | ✅ per-engine suites | mirror-only |
| 5 | Production WADE | `scanner/webhound/wade/` | `_run_wade()` (orchestrator L1964, called L728) | baseline→diff→anomaly→classify→timeline | ✅ | ✅ `test_wade*.py` | mirror-only |
| 6 | Findings | `scanner/webhound/models/finding.py`; `apps/api/models/finding.py` | `Finding`; `FindingRecord` | severity/category/engine/confidence/evidence/framework | ✅ | ✅ | no |
| 7 | Persist | `apps/api/services/result_persistence.py` | `persist_scan_result()` | called from `worker/scan_tasks.py` L302 | ✅ | ✅ `test_scan_results.py` | no |
| 8 | DB | `apps/api/models/*` + `migrations/versions/` (42) | `ScanResultRecord`/`GroupedFindingRecord`/`BaselineRecord` | Postgres + Alembic | ✅ | ✅ | no |
| 9 | Reports | `scanner/webhound/reporting/{json,pdf,markdown,csv,sarif}_report.py` | `JsonReport.build()`, `_wade_section()` | served via `routers/scan_results.py` `get_report_by_format()` | ✅ | ✅ | no |
| 10 | Frontend report | `apps/web/src/app/dashboard/results/[id]/page.tsx` | `WADESummary`, `GroupedFindingsTable`, `ReportDownloads` | renders `wade_anomaly_count` + findings | ✅ | ⚠ | no |

**Note:** `worker/report_tasks.generate_report` is a **stub** — reports are built on demand from stored scan metadata, not generated async post-scan.

---

# GOAL 3 — Advisory AI Flow Trace ("Built, not customer-facing")

| # | Step | Repo path | Function | Evidence | Active? | Class | Reaches reports? |
|---|------|-----------|----------|----------|:---:|------|:---:|
| 1 | Corpus | `corpus/{raw,normalized,indexes,manifests}` | — | normalized repos/docs/feeds/taxonomy | ✅ | local-only | ❌ |
| 2 | Chunks | `corpus/normalized/unified_chunks.jsonl` | `build_unified_chunk_index.py` | **1,161** chunks | ✅ | local-only | ❌ |
| 3 | Embeddings | `corpus/indexes/dense/` | `build_dense_index.py` | **1,161** vecs, all-MiniLM-L6-v2 (384) | ✅ | local-only | ❌ |
| 4 | Retrieval | `scripts/ai/hybrid_retrieval.py` | `HybridRetriever.retrieve()` | BM25 0.35 + dense 0.65; local | ✅ | advisory/local | ❌ |
| 5 | LightRAG | `scripts/ai/build_lightrag_index*.py` | — | **vector-only**, LLM extraction is a stub | ⚠ partial | local-only | ❌ |
| 6 | Neo4j | `scripts/ai/load_neo4j.py`, `load_brain_graph_neo4j.py` | — | local bolt:7687; no scanner/apps import | ⚠ local | local-only | ❌ |
| 7 | Graphiti | `scripts/ai/seed_graphiti.py`, `graphiti_runtime_check.py` | — | 13 episodes; needs separate install | ⚠ local | local-only | ❌ |
| 8 | Ollama | `scripts/ai/build_lightrag_index_ollama.py` | — | models: nomic-embed-text, phi3:mini | ⚠ local | local-only | ❌ |
| 9 | Advisory WADE | `scripts/wade/reasoning/` | `identify_attack_chains()`, `RootCauseReasoner`, `PriorityReasoner`, `generate_executive_summary()`, `WADEShadowReasoner` | every result `advisory_only=True`; `ShadowReasoningPackage.production_unchanged=True` | ✅ (tests/demo only) | advisory | ❌ |
| 10 | Brain interface | `docs/ai/WADE_BRAIN_INTERFACE.md` | spec only | "no implementation in prod paths" | spec | advisory | ❌ |

**Verified isolation:** import scan of all `scanner/**/*.py` and `apps/api/**/*.py` for `lightrag|neo4j|graphiti|corpus|hybrid_retrieval|semantic_retrieval|scripts.ai|scripts.wade.reasoning` → **zero matches**. `apps/api/services/ai_summary.py` (Claude, opt-in `WEBHOUND_AI_ENABLED`) consumes **only structured findings**, no corpus. **→ No advisory output reaches production scoring or reports.**

---

# GOAL 4 — Scanner Baseline

- **Engine families (11, all production-active):** headers (cors/csp/security_headers), cookies, javascript (js_analyzer/obfuscation/third_party_domains/vulnerable_libs), secrets, forms, recon (robots_sitemap/sensitive_paths/technology), compromise (hidden_iframes/injected_js/seo_spam/suspicious_redirects), cms (shopify/wix/wordpress), api_discovery, threat_intel, tls_dns. **No test-only engines** — all wired in `Scanner.scan()`.
- **Tests:** `scanner/tests/` ≈ **104** files; `apps/api/tests/` ≈ **76** files.
- **Phase status:** 9A full engine audit **MERGED** (PR #20); 9B-A coverage + validation infra **MERGED** (PR #21, = `main` HEAD); **9B-B detection hardening + measured validation OPEN (PR #22)** — hardening NOT yet on main.
- **Hardening merged vs pending:** baseline coverage merged; the measured detection-hardening improvements are **pending in PR #22**.

---

# GOAL 5 — WADE Baseline (Production vs Advisory)

**A) PRODUCTION WADE — customer-facing, wired, report-integrated**
- Path: `scanner/webhound/wade/` (`baseline_builder`, `diff_engine`, `anomaly_scorer`, `classifier`, `change_classifier`, `confidence`, `timeline`, `suppression`, `quality_review`, `vendor_intel`, `context_engine`, `baseline_store`).
- Flow: `Scanner._run_wade()` (orchestrator L1964, called L728) → `BaselineBuilder.build()` → `DiffEngine.diff_site()` → `AnomalyScorer.score()` → `Classifier.classify()` → `adjust_findings_confidence()` → `ChangeClassifier.assess_all()` → `update_timeline()`.
- Customer surface: `apps/web .../results/wade-summary.tsx` (`wade_anomaly_count`, baseline/compared flags) + `json_report._wade_section()`.
- Baselines persisted: `apps/api/models/baseline.py` `BaselineRecord`; loaded/saved by `worker/scan_tasks.py` (L184/L321).
- Tests: `scanner/tests/test_wade*.py` (×4+), `apps/api/tests/test_wade_correlation.py`.
- **Dormant cousin:** `apps/api/services/wade_correlation.py` `analyse_website()` (5 cross-scan behavioural rules) **has tests but no live call site** — not wired to any route/worker.

**B) ADVISORY WADE — shadow-only, NOT wired, does NOT reach reports**
- Path: `scripts/wade/reasoning/` (`attack_chain`, `root_cause`, `priority`, `executive`, `shadow_mode`, `correlation`, `confidence`, `graph_reasoning`, `memory_reasoning`).
- Safeguards: every output carries `advisory_only=True`; `ShadowReasoningPackage.production_unchanged=True` (structural); executive summaries customer-safe.
- Consumers: only `tests/ai/test_wade_reasoning_engine.py` + `scripts/ai/test_wade_reasoning.py` demo + internal imports.
- **Reaches reports: NO.**

---

# GOAL 6 — Knowledge Library Baseline

- Manifest records: **487** (`corpus/manifests/manifest.jsonl`). Chunks: **1,161** (`unified_chunks.jsonl`). Embeddings: **1,161** (`corpus/indexes/dense/`, all-MiniLM-L6-v2, 384-dim).
- Retrieval: hybrid (lexical 0.35 + dense 0.65) — **top-1 76% / top-3 88% / top-5 90%** (120-question test, `PHASE7A_RESULTS.md`); WADE-readiness 8.9/10.
- Authority tiers (5): A official docs/specs · B research · C official repos · D feeds/KBs (enrichment only) · E community (never security authority). Source→chunk traceability via manifest provenance + source attribution.
- `knowledge/` (12 curated categories): detection-engineering, false-positive-catalog, javascript-malware-library, owasp, playbooks, provider-docs, scanner-engines, third-party-domain-risk, threat-intel-library, threat-intelligence, vulnerability-taxonomy, webhound.
- Deprecation: none formally marked; **risk** = knowledge is mirrored across `knowledge/` + corpus + 2 vaults (see GOAL 11).

---

# GOAL 7 — Obsidian Baseline (THREE vaults)

| Vault | Path | Notes | Sections | Generated? | Obsidian app? |
|-------|------|------:|----------|:---:|:---:|
| Stub/operational | `vault/webhound` | 8 | decisions, false-positives, provider-access, research, runbooks, scanner-engines, wade | No marker | plain-MD |
| AI Brain | `vault/WebHound AI Brain` | 132 | numbered 00–25 incl. `00-Dashboard`, `00-Maps`; **duplicate numbers** (03 & 08 WADE, 04 & 13 Knowledge, 06 & 09 Threat-Intel, 08 & 11 External-Tools) | ✅ all `WEBHOUND-GENERATED` + `phase:` | no `.obsidian` |
| KNOWLEGE VAULT (typo) | `vault/WEBHOUND KNOWLEGE VAULT` | 114 | numbered 01–27 (cleaner), `99-Maps`, root dashboards | ✅ 111/114 | ✅ has `.obsidian/` |

- Wikilinks present (`[[...]]`); graph status: vault graph stats recorded (`docs/ai/vault_graph_stats.json`). Broken-link/orphan audit: **UNVERIFIED here** (not re-scanned this phase).
- Synced: AI Brain synced in Phase 8G. Generated notes are marked. The two generated vaults **overlap heavily** (same note titles).
- Missing/represented: production systems are represented (scanner/WADE/knowledge); the **3-vault split itself is the main gap** — no single canonical vault.

---

# GOAL 8 — Graph & Runtime Baseline (snapshots 2026-06-14; local-only)

| Runtime | Status (snapshot) | Counts | R/W risk | Used by prod? | Used by advisory? |
|---------|------|--------|----------|:---:|:---:|
| Neo4j | LIVE (local docker, bolt:7687) | FileNode 126; WIKI_LINK 157; DEPENDS_ON 34; other node types 0 | local write via scripts | ❌ | ⚠ scripts only |
| Graphiti | LIVE (needs `graphiti-core`) | 13 episodes; 8 memory types | local | ❌ | ⚠ scripts only |
| LightRAG | LIVE_FULL (v1.5.2) | vector storage (11 json); **graph extraction = stub** | local | ❌ | ⚠ scripts/tests |
| Ollama | reachable | models: nomic-embed-text, phi3:mini | local | ❌ | ⚠ embeds/LightRAG |

**None are imported by `scanner/` or `apps/api/`.** All local-only, not customer-facing. Current liveness UNVERIFIED (no live calls this phase).

---

# GOAL 9 — MCP Baseline

- `.mcp.json`: **only `claude-flow`** (`npx … ruflo@latest mcp start`, `autoStart:false`), mirrored in `.codex/config.toml`. No API-key env vars.
- Documented-only (5): Filesystem, GitHub, Playwright, Firecrawl, Perplexity (`docs/ai/mcp/`).
- Inferred/category candidates (~16 more) from the Phase-7 roadmap (7A–7J) — see PR #24.
- Active: 1 (claude-flow, dev orchestration). Installed as package: 0. **MCPs touching production: NONE.**
- PR #24 (Phase 8Z-A) = full MCP reconciliation, **OPEN**. **No `.mcp.json` edit / no install in this phase.**

---

# GOAL 10 — Tooling Baseline

| Tool | Status |
|------|--------|
| Nuclei, ZAP, sqlmap, XSStrike, DalFox, Semgrep, Gitleaks, Firecrawl, Katana, httpx(PD binary) | **knowledge-only** (ingested docs in `corpus/`/`knowledge/`) |
| Burp, Trivy, OSV, Subfinder, dnsx | **not found** (no docs, no deps) |
| Playwright | **production-integrated, opt-in** (`scanner/webhound/browser/playwright_runner.py`, gated by `WEBHOUND_BROWSER_ENABLED`; `playwright==1.60.0` in `.venv-api`) — distinct from Playwright **MCP** (knowledge-only) |
| httpx (Python lib) | **production** HTTP client (`httpx>=0.27`) — distinct from PD `httpx` binary |
| dnspython | **production** DNS lib (`dnspython>=2.6`) — distinct from PD `dnsx` |

---

# GOAL 11 — Confusion & Duplicate Map

| # | Name | Why confusing | Recommended cleanup | DO NOT DELETE unless approved |
|---|------|---------------|---------------------|:---:|
| 1 | Two "WADE" | `scanner/webhound/wade/` (production) vs `scripts/wade/reasoning/` (advisory shadow) share the name | Rename advisory to **WADE-Advisory / Shadow-WADE** in docs + folder README; never in code without approval | ✅ |
| 2 | Three Obsidian vaults | `vault/webhound` (stub) + `vault/WebHound AI Brain` (132, generated) + `vault/WEBHOUND KNOWLEGE VAULT` (114, generated, typo) | Pick **one** canonical generated vault; mark the other "archived"; fix "KNOWLEGE" typo only on the keeper | ✅ |
| 3 | Four graph/runtime systems | Neo4j + Graphiti + LightRAG + Ollama all "live" but none production-wired → look connected, aren't | Add a "LOCAL-ONLY / ADVISORY" banner to each runtime doc | ✅ |
| 4 | Duplicate vault section numbers | AI Brain has `03/08-WADE`, `04/13-Knowledge`, `06/09-Threat-Intel`, `08/11-External-Tools` | Renumber on the chosen canonical vault only | ✅ |
| 5 | Knowledge mirrored 4× | same content in `knowledge/` + `corpus/normalized/` + 2 vaults | Declare `corpus/` the source of truth; vaults/`knowledge/` are derived views | ✅ |
| 6 | Dormant WADE correlation | `apps/api/services/wade_correlation.py` looks production but has no call site | Doc as "dormant; wire in a future gated phase" | ✅ |
| 7 | Stub report task | `worker/report_tasks.generate_report` reads as live async report gen but is a placeholder | Doc as stub | ✅ |
| 8 | Duplicate phase numbering | many 8x variants (8A–8G, 8X, 8Y, 8Z-A) + 9A/9B-A/9B-B across PRs | This doc + PR decision map (GOAL 13) is the index | ✅ |
| 9 | claude-flow vs ruflo naming | `.mcp.json` runs `ruflo@latest`; `CLAUDE.md` documents `@claude-flow/cli` | Note the alias in one place | ✅ |

---

# GOAL 12 — WebHound Linkage Matrix

| System | Exists | Tested | Production | Advisory | →WADE | →Reports | →Obsidian | Dup risk | Next action |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| Scanner | ✅ | ✅ (104) | ✅ | – | feeds | ✅ | mirror | low | merge PR #22 |
| Production WADE | ✅ | ✅ | ✅ | – | self | ✅ | mirror | **high (name)** | rename advisory, not this |
| Advisory WADE | ✅ | ✅ (tests) | ❌ | ✅ | shadow | ❌ | mirror | **high (name)** | label as shadow |
| Knowledge Library | ✅ | ✅ (retrieval) | ❌ | ✅ | via brain iface (spec) | ❌ | source | med (mirrored) | declare corpus canonical |
| Obsidian | ✅×3 | n/a | ❌ | ✅ | – | ❌ | self | **high (3 vaults)** | pick one canonical |
| Neo4j | ⚠ local | smoke | ❌ | ⚠ | ❌ | ❌ | – | med | LOCAL-ONLY banner |
| Graphiti | ⚠ local | smoke | ❌ | ⚠ | ❌ | ❌ | – | med | LOCAL-ONLY banner |
| LightRAG | ⚠ local | smoke | ❌ | ⚠ | ❌ | ❌ | – | med | note vector-only stub |
| Ollama | ⚠ local | smoke | ❌ | ⚠ | ❌ | ❌ | – | low | note local-only |
| MCPs | ✅ (1 live) | n/a | ❌ | dev only | ❌ | ❌ | – | low | PR #24; no install |
| Reports | ✅ | ✅ | ✅ | – | shows WADE | self | no | low | keep |

---

# GOAL 13 — Open PR Decision Map

| PR | Branch | Purpose | Files | Prod impact | Merge rec | Why | Next dep |
|----|--------|---------|-------|:---:|-----------|-----|----------|
| **#22** | `feat/scanner-phase-9b-b-detection-hardening` | 9B-B detection hardening + measured validation | scanner engines + tests | **YES (scanner)** | **MERGE (1st)** | only open PR improving the production product; tested + CI green; in-flight 3+ days | unblocks 9C |
| #23 | `feat/tooling-phase-8x-integration-audit` | 8X ecosystem/tooling audit | docs (`TOOLING_INVENTORY.md`, `PHASE8X_RESULTS.md`) | none | MERGE (batch) | pure docs; safe; superseded-by-CONTROL-1 partly but still the tooling source | none |
| #24 | `feat/mcp-phase-8z-a-master-reconciliation` | 8Z-A MCP reconciliation | docs (`docs/ai/MCP_*`) | none | MERGE (batch) | pure docs; safe; canonical MCP map | precedes 8Z-B |
| #2 | dependabot esbuild | bump esbuild (apps/web) | lockfile | dev only | review/merge | security bump; verify build | none |
| *(this)* | `feat/control-1-system-baseline-linkage-map` | CONTROL-1 current-state | docs + 1 vault note | none | MERGE (batch) | the source-of-truth map | none |

---

# GOAL 14 — Next Single Move

**MERGE PR #22 (Phase 9B-B Detection Hardening + Measured Validation).**

**Why (one reason, clearly):** It is the **only open PR that improves the actual production scanner customers use**, it is already **tested with measured validation and CI-green**, and it has been in-flight since 2026-06-15. Merging it *completes* in-flight core work rather than starting anything new — exactly the "stop adding, finish what exists" posture this phase calls for. The three doc PRs (#23, #24, this one) are zero-production-risk and can be batch-merged immediately after; **8Z-B / 8Y / 9C and any vault consolidation should wait** until #22 lands and the board is clear.

*Not five moves — one: merge #22.*

---

*Companion: [`PHASE_CONTROL_1_RESULTS.md`](PHASE_CONTROL_1_RESULTS.md). Vault mirror: `vault/WebHound AI Brain/00-Dashboard/WEBHOUND_CURRENT_STATE.md`.*
</content>
