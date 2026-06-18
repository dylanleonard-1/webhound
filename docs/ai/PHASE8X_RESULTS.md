# Phase 8X — Complete Ecosystem Tooling & MCP Integration Audit
**Date:** 2026-06-17 | **Branch:** feat/tooling-phase-8x-integration-audit
**Method:** 6 parallel audit agents (scanner, wade, graph, knowledge, api, mcp) — read-only
**Security guardrails:** AUDIT ONLY. No production/scanner/WADE-scoring/provider-access/.mcp.json/billing/auth modified.

> **Harness flag — WADE agent:** Harness classifier flagged a possible classifier-bypass pattern in the WADE/AI-brain audit agent output. Output was reviewed in full; no actionable directive was found. All findings are treated as factual code-audit data only.

---

## STATE OF THE WEBHOUND ECOSYSTEM

| Subsystem | Completeness | Status |
|-----------|-------------|--------|
| Scanner engines (31) | **95%** | GREEN — all wired; async engines need live HTTP |
| WADE core (baseline/diff/anomaly/classify) | **100%** | GREEN — fully production-wired |
| API infrastructure (FastAPI/Celery/PostgreSQL) | **90%** | GREEN — live on Railway/Vercel |
| Threat intelligence (12 modules) | **80%** | GREEN — wired; VirusTotal needs API key |
| Reporting (findings → DB → UI) | **70%** | YELLOW — AI summary opt-in only |
| Cross-scan WADE correlation | **50%** | YELLOW — exists, optional post-scan |
| Knowledge corpus (built/indexed) | **85%** | YELLOW — built, not queried by prod |
| WADE advisory/reasoning (9 modules) | **0%** | RED — isolated, not called from prod |
| AI/graph layer (Neo4j/LightRAG/Graphiti/Ollama) | **15%** | RED — local vectors only; graph blocked |
| MCP ecosystem (6 planned) | **17%** | RED — 1 of 6 active |
| Security tool automation (Nuclei/ZAP/etc.) | **0%** | RED — knowledge-docs only |

**Unweighted average: ~62%** | **Production-weighted average (scanner 30%, API 20%, WADE 15%, rest split): ~74%**

The product can scan a site end-to-end today and produce a risk score, grouped findings, and WADE anomaly detection. The missing 26–38% is the AI enrichment path: attack-chain reasoning, knowledge-augmented advisories, and graph-assisted context.

---

## RED / YELLOW / GREEN SCORECARD

### GREEN — Production-wired, tested, deployed
- 31 scanner engines, 23-phase pipeline, all connected
- WADE core: BaselineBuilder → DiffEngine → AnomalyScorer → Classifier → Findings
- Celery queue (Redis broker): scan tasks, scheduled scans, stale-job reaper
- PostgreSQL schema: 20+ migrations, Finding/GroupedFinding/ScanResult/Baseline/Alert models
- Vercel + Cloudflare managed integrations (bypass headers, WAF rules)
- VirusTotal + URLhaus threat clients, 12 threat intel modules
- FP filter, correlation clustering, risk scoring (0–100), security stories
- Scanner advisor modules: ChangeExplainer, RiskExplainer, PriorityExplainer, ActionPlan (scanner-internal)
- WADE baseline API endpoints (GET baselines, WADE summary)
- Rate limiting, quota enforcement, scan cooldown (60s/domain/user)
- Multi-engine correlation (cross-engine cluster → possible-compromise grouping)

### YELLOW — Exists but not default-on or not in production path
- Claude AI summary (`ai_summary.py`): wired, validated, but off unless `WEBHOUND_AI_ENABLED=1` + key
- Playwright browser engine: opt-in via `WEBHOUND_BROWSER_ENABLED`; lazy-loaded; safe-mode
- Cross-scan WADE correlation (`wade_correlation.py`): wired but `best-effort` / optional post-scan
- Knowledge corpus (4,600 chunks, 1.70 MB embeddings): built, not queried by prod scanner
- LightRAG vectors (1.85 MB): local only; not reachable from `apps/api`
- Obsidian vault (135 notes): curated manually, no automated production path
- `ruvector.db`: active for claude-flow agent memory, not WebHound knowledge

### RED — Missing from production path
- WADE reasoning modules (`scripts/wade/reasoning/*.py`): 9 modules, tested in isolation, never called from `orchestrator.py`
- WADE retrieval service (`scripts/wade/retrieval_service.py`): built, never called from prod
- Neo4j: configured in `docker-compose-neo4j.yml`, not running, not deployed
- Graphiti: scaffolded, requires Neo4j + Ollama, not running
- Ollama: configured in `docker-compose.ai-brain.yml`, no models pulled, not deployed
- LightRAG graph extraction: blocked by stub LLM (requires real Ollama model)
- 5 of 6 planned MCPs: Filesystem, GitHub, Playwright, Firecrawl, Perplexity — documented, not installed
- Security tool binaries (Nuclei, ZAP, sqlmap, XSStrike, DalFox, libinjection, Semgrep, Gitleaks, Trivy, Katana, httpx CLI, dnsx, subfinder, Amass, Firecrawl): knowledge docs only

---

## SIX MOST-IMPORTANT ANSWERS

### 1. Which envisioned tools are NOT actually integrated into the scanner?
| Category | Not Integrated |
|----------|---------------|
| Security tool binaries | Nuclei, ZAP, sqlmap, XSStrike, DalFox, libinjection, Semgrep, Gitleaks, Trivy, Katana, httpx (CLI), dnsx, subfinder, Amass, Firecrawl — all ingested as knowledge docs |
| MCP servers | Filesystem, GitHub MCP, Playwright MCP, Firecrawl MCP, Perplexity — documented in `docs/ai/mcp/`, not in `.mcp.json` |
| WADE reasoning | `scripts/wade/reasoning/*.py` (9 modules: attack_chain_builder, root_cause_analyzer, priority_ranker, etc.) — built, tested, never called from `orchestrator.py` |
| Graph AI | Neo4j, Graphiti, Ollama — configured in docker-compose, not running/deployed |
| Knowledge retrieval | 4,600-chunk corpus + 1.70 MB embeddings + LightRAG vectors — built but no production query path |

**Note:** `httpx` (Python library) and Playwright (browser library) ARE production-integrated. The table above refers to the ProjectDiscovery CLI binaries.

### 2. Which MCPs are installed but unused?
**None.** The only installed MCP is `claude-flow` (orchestration/memory). It is actively used for agent coordination. There are no installed-but-unused MCPs. The problem runs the other direction: 5 planned MCPs are documented but never installed.

### 3. Which tools produce data but never reach WADE?
| Tool / Layer | Data Produced | Reaches WADE? |
|-------------|--------------|---------------|
| LightRAG vectors | 1.85 MB semantic embeddings | NO |
| Knowledge corpus | 4,600 scored chunks | NO |
| Neo4j graph | (not running) | NO |
| Graphiti episodes | (not running) | NO |
| `scripts/wade/retrieval_service.py` | Advisory context objects | NO — never called |
| Obsidian vault notes | 135 curated threat/provider notes | NO |
| `scripts/wade/reasoning/*.py` | Attack chains, root-cause, priority analysis | NO — not wired |
| `apps/api/services/wade_correlation.py` | Cross-scan behavioural anomalies | PARTIAL — optional post-scan |

### 4. Which things reach WADE but never reach customer-facing reports?
| Component | Status |
|-----------|--------|
| `wade/quality_review.py` | Produces advisory metadata; not stored in DB, not shown in reports |
| `advisor/change_explainer.py` (scanner-internal) | Builds change narrative; flows into finding descriptions at scan time |
| `apps/api/services/ai_summary.py` | AI summary computed on-demand per request; not persisted in DB by default; off unless `WEBHOUND_AI_ENABLED=1` |
| WADE `Suppression` output | Supressed-alert annotations; internal audit trail only |
| `QualityReview` advisory metadata | Internal, not serialized to finding records |

### 5. Is any live-tool execution (Nuclei, ZAP, sqlmap, etc.) happening in the production scanner?
**No.** Every named security tool was ingested as knowledge documentation for the corpus/knowledge layer. No subprocess calls, no shell execution, no binary invocations exist in `scanner/`, `apps/`, or `worker/`. The scanner is implemented entirely in Python using `httpx`, `dnspython`, `beautifulsoup4`, `lxml`, and `tldextract`. Playwright (opt-in browser runner) is the only external process launched, and only when `WEBHOUND_BROWSER_ENABLED` is set.

### 6. What is the single biggest gap before launch?
**The WADE advisory reasoning layer (`scripts/wade/reasoning/`) is complete but entirely disconnected from the production scan→finding→report pipeline.** A customer scan today yields anomaly scores and baseline diffs (WADE core), but receives no attack-chain analysis, no root-cause explanation, and no AI-prioritized remediation narrative. The `scripts/wade/retrieval_service.py` and 9 reasoning modules exist and are tested in isolation. Wiring them into `orchestrator._run_wade()` as an optional post-phase enrichment step (identical guardrail pattern to how AI summary is gated by `WEBHOUND_AI_ENABLED`) is the highest-impact single change — it would surface the full Phase 8 knowledge investment to every customer report without touching production scoring.

---

## TOP 25 MISSING ITEMS

| # | Item | Category | Effort | Impact |
|---|------|----------|--------|--------|
| 1 | Wire `scripts/wade/reasoning/` into `orchestrator._run_wade()` as opt-in enrichment | WADE advisory | M | CRITICAL |
| 2 | Enable Claude AI summary by default (or prompt-on-first-result) | Reporting | S | HIGH |
| 3 | Wire `scripts/wade/retrieval_service.py` to serve knowledge-augmented finding context | Knowledge | M | HIGH |
| 4 | Nightly SAFE_TARGET_MATRIX CI gate (Phase 9C) — automated precision/recall regression | QA | M | HIGH |
| 5 | Deploy Neo4j + run graph extraction (unblock LightRAG full graph) | Graph AI | L | HIGH |
| 6 | Pull Ollama + embed a base model (`nomic-embed-text`) for local graph extraction | Graph AI | M | HIGH |
| 7 | Install GitHub MCP server — enables PR scanning, repo-level context | MCP | S | MEDIUM |
| 8 | Install Filesystem MCP server — enables local repo scan workflow | MCP | S | MEDIUM |
| 9 | Install Playwright MCP server — enables browser-automated scan sessions | MCP | S | MEDIUM |
| 10 | Install Firecrawl MCP server — enables rich content extraction in AI context | MCP | S | MEDIUM |
| 11 | `wade_correlation.analyse_website()` called automatically post-scan (not optional) | WADE | S | MEDIUM |
| 12 | Persist AI summary in DB (new `ai_summary_text` field on ScanResult) | Reporting | S | MEDIUM |
| 13 | Expose attack-chain narrative in `/scan-results/{id}` API response | API | M | MEDIUM |
| 14 | Add `WEBHOUND_BROWSER_ENABLED` to Railway environment defaults | Infra | S | MEDIUM |
| 15 | Merge Phase 9B-B FP hardening (PR #22) to main | FP quality | S | MEDIUM |
| 16 | Deploy Graphiti against Neo4j for provider-specific episode memory | Graph AI | L | MEDIUM |
| 17 | Add `reasoning_summary` field to Finding DB model (advisory output) | DB | S | LOW-MEDIUM |
| 18 | Install Perplexity MCP — real-time CVE lookup during scan advisory | MCP | S | LOW-MEDIUM |
| 19 | VirusTotal API key configured in Railway env | Threat intel | S | LOW-MEDIUM |
| 20 | Nuclei template library as Celery task (opt-in active scan profile) | Scanner | XL | LOW (future) |
| 21 | Semgrep SAST integration for code-level findings | Scanner | L | LOW (future) |
| 22 | Gitleaks secret scan integration | Scanner | L | LOW (future) |
| 23 | Subfinder/Amass passive subdomain enumeration in deep profile | Scanner | L | LOW (future) |
| 24 | Knowledge corpus query endpoint (`/ai/search`) for advisory retrieval | API | M | LOW |
| 25 | Katana crawler integration as deep-profile alternative to built-in crawler | Scanner | L | LOW (future) |

---

## COMPLETENESS BY PHASE-8X GOAL

| Goal | Finding | Status |
|------|---------|--------|
| 1. Map all 31 scanner engines | All 31 engines confirmed wired into 23-phase pipeline | COMPLETE |
| 2. Audit WADE production integration | Core WADE: 100% — `orchestrator._run_wade()` fully wired | COMPLETE |
| 3. Audit WADE advisory isolation | 9 reasoning modules + retrieval: ISOLATED, 0% in production | COMPLETE |
| 4. Map MCP inventory | 1 of 6 active (claude-flow only) | COMPLETE |
| 5. Audit security tool integration | 15 tools: ALL knowledge-docs only, zero subprocess calls | COMPLETE |
| 6. Audit AI/graph layer | Neo4j/Graphiti/Ollama not running; LightRAG local-only | COMPLETE |
| 7. Map knowledge corpus | 4,600 chunks, 277 files, 135 vault notes — no prod query path | COMPLETE |
| 8. Audit threat intelligence | 12 modules production-wired; VirusTotal needs key | COMPLETE |
| 9. Audit API infrastructure | FastAPI + Celery + PostgreSQL + Redis — fully live | COMPLETE |
| 10. Audit report generation | Findings→DB→UI complete; AI summary opt-in only | COMPLETE |
| 11. Audit provider detection | 50+ providers hard-coded in discovery.py; Vercel + CF API integrations | COMPLETE |
| 12. Audit DB schema | 20+ models; no WADE reasoning or AI summary fields stored | COMPLETE |
| 13. Audit auth/security middleware | JWT + bcrypt + rate limiting + SSRF guard + input validation | COMPLETE |
| 14. Audit Celery/queue | 9 task modules, beat schedule, soft/hard limits, stale-job reaper | COMPLETE |
| 15. Audit false-positive hardening | Phase 9B-B: 4 fixes, 34 tests, 2645/2645 passing — PR #22 open | COMPLETE |
| 16. Produce ecosystem completeness % | See scorecard: unweighted 62%, prod-weighted ~74% | COMPLETE |
| 17. Identify single biggest gap | WADE reasoning modules disconnected from prod report path | COMPLETE |

---

## VALIDATION

**Zero production changes made.** This audit is read-only. No modifications to:
- `scanner/webhound/` (scanner engines or scoring)
- `apps/api/` (API routes, billing, auth)
- WADE scoring or provider-access files
- `.mcp.json`
- Any production configuration

**Branch:** `feat/tooling-phase-8x-integration-audit` diverges from `main` with this document and `TOOLING_INVENTORY.md` only.

---

## RECOMMENDED NEXT PHASES

| Phase | Scope | Priority |
|-------|-------|----------|
| 9B-B merge | Merge PR #22 FP hardening to main | IMMEDIATE |
| 9C | Live SAFE_TARGET_MATRIX validation against approved safe targets | HIGH |
| 9D | Wire WADE reasoning modules into prod (opt-in enrichment, same gating as AI summary) | HIGH |
| 9E | Deploy Neo4j + unblock LightRAG graph extraction | MEDIUM |
| 9F | Install 5 remaining MCPs (GitHub, Filesystem, Playwright, Firecrawl, Perplexity) | MEDIUM |
