# WebHound AI Knowledge Layer — Master Plan (Phase 0 Output)

**Status:** PLANNING ONLY. Nothing implemented, installed, or modified. This document is the sole deliverable of Phase 0.
**Date:** 2026-06-12
**Branch inspected:** `main` @ `8648dab` (working tree has only pre-existing untracked/modified artifacts — see §1).
**Constraint reminder:** Phase 1 starts only on explicit approval. Each phase is its own approval-gated stop point.

> Grounding rule applied throughout: every "exists" claim below was verified by direct repo inspection. Anything I could not verify is marked **UNKNOWN** or **UNVERIFIED**. I did **not** invent endpoints, keys, permissions, or provider behavior. `.env` / `.env.example` are **permission-blocked in this environment**, so concrete env-key inventories are marked UNVERIFIED.

---

## 1) Current repo findings (Phase 0 — all 20 inspection items)

| # | Item | Finding |
|---|------|---------|
| 1 | Current branch | `main` (post-merge of `feat/platform-access-framework`). |
| 2 | Git status | Clean except pre-existing: modified `.claude/settings.local.json`, `apps/web/package-lock.json`, `apps/web/tsconfig.tsbuildinfo`; untracked `WEBHOUND_*.md` analyses, `scripts/bench/`, `scripts/prod_scan_metrics.py`, `.agents/`, `skills-lock.json`. No in-flight feature work. |
| 3 | Repo structure | Monorepo: `apps/api` (FastAPI), `apps/web` (Next.js), `scanner/` (the `webhound` Python engine package), `worker/` (Celery), `packages/` (`configs`, `shared-types`), `infra/`, `docs/`, `scripts/`. Root `webhound/` shim + `ruvector.db` + `railway.toml`. |
| 4 | Docs folders | `docs/` (rich markdown: `architecture.md`, `scanner-engines.md`, `wade.md`, `database-schema.md`, `api-routes.md`, `telemetry-foundation-design.md`, `roadmap.md`, `secret-management.md`, `safety-authorization-notice.md`, etc.) + `apps/web/src/app/(marketing)/docs`. ~16 root `*.md` (CLAUDE.md, README, SECURITY_NOTICE, KNOWN_LIMITATIONS, plus WEBHOUND_* audits). **No `docs/ai/` exists.** |
| 5 | Scanner engine folders | `scanner/webhound/` packages: `advisor`, `asm`, `auth`, `benchmark`, `browser`, `core`, `engines`, `frameworks`, `graph`, `industry`, `models`, `monitoring`, `portfolio`, `providers`, `reporting`, `telemetry`, `threat_intel`, `utils`, `wade`, `identity.py`. **`engines/`** contains: `api_discovery`, `cms`, `compromise`, `cookies`, `forms`, `headers`, `javascript`, `recon`, `secrets`, `tls_dns`, `threat_intel`. |
| 6 | WADE code | **Exists, substantial.** `scanner/webhound/wade/`: `anomaly_scorer`, `baseline_builder`, `baseline_store`, `change_classifier`, `change_types`, `classifier`, `confidence`, `context_engine`, `diff_engine`, `quality_review`, `suppression`, `timeline`, `vendor_intel`. API side: `apps/api/services/wade_correlation.py` + `apps/api/tests/test_wade_correlation.py`. Scanner tests: `test_wade*.py` (×4). Web: `wade-summary.tsx`, `wade-history-timeline.tsx`, `/(marketing)/wade`. Docs: `docs/wade.md`. |
| 7 | Threat-intel code | **Exists, substantial.** `scanner/webhound/threat_intel/`: `feed_manager`, `feed_normalizer`, `urlhaus_client`, `virustotal_client`, `enrichment_service`, `domain_reputation`, `domain_classifier`, `reputation_cache`, `script_reputation`, `supply_chain`, `brand_impersonation`, `threat_correlation`, `coverage`. API side: `apps/api/services/threat_intel.py`, `apps/api/internal/threat_intel.py`, `apps/api/models/threat_indicator.py`, migration `0024_threat_intel.py`, web control page `/control/threat-intel`. **Confirmed feed clients: URLHaus, VirusTotal.** ThreatFox/OpenPhish/OTX/AbuseIPDB are referenced in normalizer/coverage but **UNVERIFIED** whether each has a live ingestion client (needs deeper read in a later phase). |
| 8 | Support/ticket code | **Exists.** `apps/api/services/support.py`, `support_ticket.py`, `tickets.py`; model `support_ticket.py`; `internal_note.py` model; tests `test_customer_tickets.py`. The just-merged platform-access support escalation calls into this (`/platform-access/support-ticket`). |
| 9 | Provider-access code | **Exists, recently expanded (merged this session).** `apps/api/services/`: `provider_access_registry.py` (10 providers), `platform_access.py`, `provider_discovery.py`, `provider_oauth.py`, `access_validation.py`, `trusted_access.py`, `scanner_access_diagnosis.py`, `cloudflare*.py` (×5), `vercel*.py` (×3). Models: `provider_connection.py`, `provider_profile.py`, `access_validation.py`, `trusted_access.py`. |
| 10 | Telemetry/audit | **Exists.** API: `observability.py`, `telemetry.py`, `phase3_audit.py`, `cloudflare_telemetry.py`; model `admin_audit_log.py`. Scanner: `telemetry/` with `events`, `exporters`, `recorder`, `redaction`, `search` (note: **redaction** module already exists — relevant to corpus PII/secret governance). |
| 11 | Test structure | pytest-based. **`apps/api/tests` = 77 files; `scanner/tests` = 99 files.** Frontend: vitest (`*.test.ts` in `apps/web/src/lib`). Conftest backs SQLite in-memory + fakeredis + opt-in `TEST_DATABASE_URL` (added this session). Scanner `validation/` adds benchmark/ground-truth tooling (see §2). |
| 12 | Scripts folder | `scripts/`: `setup_dev.sh`, `start_dev.sh`, `start_prod.sh`, `run_migrations.sh`, `run_scan.sh`, `seed_db.py`, `seed_demo.py`, `create_admin.py`, `promote_admin.py`, `smoke_check.py`, `backend_e2e_check.py`, `audit_runtime_config.py`, `_gen_env_example.py`, `prod_scan_metrics.py`, `fixtures/sample_scan_result.json`, `bench/` (untracked). **No `scripts/ai/`.** |
| 13 | Env example files | `.env` and `.env.example` exist at root; a generator `scripts/_gen_env_example.py` exists. **Both `.env*` are PERMISSION-BLOCKED in this environment** → exact key list **UNVERIFIED**. From `config.py` (readable): `anthropic_api_key` (gated by `WEBHOUND_AI_ENABLED`), `resend_api_key`, `twilio_auth_token`, Vercel integration (oac_* client id/secret + slug). **No `GITHUB_TOKEN`/`FIRECRAWL_API_KEY`/`PERPLEXITY_API_KEY`/`OTX`/`ABUSEIPDB`/`THREATFOX` keys found in `config.py`** (would be new additions). |
| 14 | Docker/compose | `docker-compose.yml` + `.dev.yml` + `.prod.yml`; `infra/docker/` (`Dockerfile.api`, `.web`, `.web.dev`, `.worker`); `infra/docker-compose.yml`, `infra/nginx/`, `railway.toml`, `infra/railway.worker.toml`. Compose includes `postgres:16-alpine` + `redis:7-alpine`. |
| 15 | Python package mgmt | pip/venv (no poetry). `scanner/pyproject.toml` + `scanner/requirements.txt`; `apps/api/requirements.txt` + `requirements-dev.txt`. Local venvs: `.venv-api`, `scanner/venv`/`scanner/.venv`. No root `pyproject.toml`. |
| 16 | Node package mgmt | npm (lockfile `apps/web/package-lock.json`). `apps/web/package.json` (`webhound-web`) + `packages/{configs,shared-types}`. Root `package.json` **not found at top level** → workspace wiring UNVERIFIED (likely app-local). |
| 17 | CI configuration | **NONE.** No `.github/workflows`. Deployment is platform-driven (Railway watch-patterns for API/worker; Vercel for web). **Gap: no CI to enforce knowledge-layer tests/governance.** |
| 18 | Security tooling | **No repo-self SAST/secret-scan in pipeline** (no gitleaks/semgrep/trufflehog/bandit/trivy/codeql config found). Note: the *product* has a `secrets` scanner engine + `encrypted_secret` model + `telemetry/redaction`, but that's runtime scanning, not the repo's own CI. `SECURITY_NOTICE.md` + `docs/secret-management.md` exist. |
| 19 | Knowledge/docs system | Markdown docs only (`docs/`). **No RAG / vector-knowledge / MCP-docs / Obsidian / corpus / `knowledge/` tree.** `ruvector.db` (root, ~1.5MB) is a claude-flow/ruv vector store (separate tooling, not a WebHound knowledge base). `.mcp.json` configures **only** `claude-flow` (`autoStart: false`); claude-flow skills under `.claude/skills/` + `.agents/skills` + `skills-lock.json`. **None of the Phase-1 target MCPs (Filesystem/GitHub/Playwright/Firecrawl/Perplexity) are configured.** |
| 20 | DB models (relevant) | `finding.py` (`FindingRecord`: severity, category, scanner_engine, confidence, evidence JSON, framework JSON, remediation, affected_url), `grouped_finding.py`, `suppression.py`, `scan_result.py`, `scan_job.py`, `scan_delta.py`, `baseline.py`, `threat_indicator.py`, `support_ticket.py`, `internal_note.py`, `provider_connection.py`, `provider_profile.py`, `access_validation.py`, `trusted_access.py`, `engine.py`, `engine_diagnostic.py`, `incident.py`, `admin_audit_log.py`, `encrypted_secret.py`. **42 Alembic migrations.** |

---

## 2) Existing systems detected (substrate the knowledge layer must reuse, not duplicate)

The master-plan target end-state assumes much is greenfield. **It is not.** WebHound already has production substrate that overlaps several proposed phases. The knowledge layer should sit **on top of / beside** these, never re-implement them:

- **Threat intelligence (runtime):** full `scanner/webhound/threat_intel/` package with URLHaus + VirusTotal clients, `feed_manager`, `feed_normalizer`, `enrichment_service`, `domain_reputation`/`script_reputation`/`reputation_cache`, `supply_chain`, `brand_impersonation`, `threat_correlation`; API `threat_indicator` model + migration + service + control UI. → **Phase 5 (threat-feed ingestion) overlaps heavily.** The knowledge-layer corpus is for *evidence/RAG* (provenance-stamped docs), which is distinct from this runtime indicator store, but ingestion scripts must not duplicate existing feed clients.
- **WADE (drift/anomaly):** full `scanner/webhound/wade/` package + `apps/api/services/wade_correlation.py`. → **Phase 8 (WADE enrichment interface) must integrate with these existing modules and the `FindingRecord` shape, not invent a parallel WADE.**
- **Detection-quality substrate:** `scanner/validation/` (`ground_truth.py`, `precision_report.py`, `recall_report.py`, `regression_runner.py`, `finding_validator.py`, `framework_scorecard.py`, `coverage_report.py`) + `scanner/webhound/benchmark/harness.py` + scanner tests `test_benchmark_harness.py`, `test_scanner_quality_phase{1,2,3}.py`. → **Phases 7/9/10 (goldens, audit, benchmarks) have real existing scaffolding to extend.**
- **Graph:** `scanner/webhound/graph/` (`graph_builder`, `graph_query`, `graph_scoring`, `relationship_extractor`, `models`). → **Phase 4 (LightRAG graph) should reconcile with this; note known FP #4 is a third-party-domain graph ingestion bug.**
- **Provider access:** the merged framework (registry of 10 providers, Cloudflare API automation, Vercel manual/`pending_firewall_setup`). → **authoritative source for "provider remediation" knowledge; provider behavior is already encoded and must be the ground truth, not re-derived.**
- **AI path already present:** `WEBHOUND_AI_ENABLED` flag + `anthropic_api_key` in `config.py` (Claude summary path; `test_ai_summary.py`). → **Phase 4 "Claude memory summaries" and enrichment should align with this existing flag/gating.**
- **Telemetry redaction + secret management:** `scanner/webhound/telemetry/redaction.py`, `encrypted_secret` model, `docs/secret-management.md`. → **reusable for corpus secret/PII governance (Phases 2/5/8 safety rules).**

**Implication:** the genuinely greenfield parts are: MCP foundation (Phase 1), the **evidence corpus + manifest/provenance** (Phase 2), the **curated knowledge/ library tree** (Phase 3), the **RAG/graph/Obsidian/memory planes** (Phase 4), the **playbook/prompt library** (Phase 6), and the **enrichment *interface* contract** (Phase 8 — interface is new even though WADE/TI internals exist).

---

## 3) Proposed architecture (grounded; additive; non-disruptive)

Layered evidence stack (A–E authority tiers per the master plan), realized as a set of **new, isolated top-level trees** plus **thin, opt-in integration points** into existing code. Nothing in `apps/`, `scanner/`, or `worker/` runtime paths changes until an explicitly-approved later phase.

```
(NEW, additive)                          (EXISTING, reused read-only in early phases)
docs/ai/            ← MCP + corpus docs   scanner/webhound/threat_intel/   ← runtime TI
corpus/             ← raw+normalized       scanner/webhound/wade/           ← runtime WADE
  raw/ normalized/ graph/ manifests/ logs/ scanner/validation/             ← goldens/metrics
knowledge/          ← curated library      apps/api/models/finding.py       ← enrichment anchor
scripts/ai/         ← ingestion/tooling    apps/api/services/wade_correlation.py
datasets/           ← inert goldens        .mcp.json                        ← MCP registry
prompts/            ← playbooks            ruvector.db / claude-flow        ← existing vector tooling
benchmarks/ audits/ dashboards/ ← later phases
apps/api/services/knowledge_enrichment/  ← Phase 8 interface (new, suggest-only)
```

**Planes (Phase 4):** raw evidence (immutable, provenance-stamped) → normalized retrieval chunks → graph/index (LightRAG/Qdrant — **note existing `ruvector.db`; decide reuse vs. new in Phase 4, do not assume**) → operator plane (Obsidian human curation + compact Claude memory summaries/pointers only).

**Hard separation:** corpus/knowledge = *evidence for the auditor*. It is **not** wired into the live scanner scoring until Phase 8, and even then **suggest-only** (no auto-suppress/severity-change).

---

## 4) Phase list (approval-gated stop points)

| Phase | Title | Output type | Gate |
|------|-------|-------------|------|
| 0 | Repo inspection + plan | **This document** | ✅ produced; awaiting review |
| 1 | MCP foundation | docs + scripts + `.env.example` additions only | needs approval |
| 2 | Evidence store + source manifest | `corpus/` skeleton + manifest schema docs | needs approval |
| 3 | Knowledge library structure | `knowledge/` tree + READMEs + starter FP catalog | needs approval |
| 4 | RAG/graph/memory architecture | docs + setup scripts + sample ingest | needs approval |
| 5 | Ingestion pipeline | ingestion scripts (dry-run) + normalized TI schema | needs approval |
| 6 | Prompt/playbook library | `prompts/` docs | needs approval |
| 7 | Synthetic datasets/goldens | `datasets/` + inert fixtures | needs approval |
| 8 | WADE knowledge enrichment interface | `knowledge_enrichment/` interface + tests (suggest-only) | needs approval |
| 9 | Engine audit preparation | `audits/` framework docs | needs approval |
| 10 | Benchmark/mass-test plan | `benchmarks/` plan docs | needs approval |
| 11 | Dashboards/monitoring | `dashboards/` plan docs | needs approval |

Order principle (from master plan): evidence backbone → source inventory → metadata schema → raw → normalized → retrieval/graph → Obsidian → memory summaries → playbooks → enrichment. **Do NOT start with memory plugins.**

---

## 5) Exact Phase 1 implementation plan (MCP foundation) — for the NEXT approval

**Goal:** stand up a minimal, least-privilege MCP foundation as **documentation + prereq/smoke scripts + `.env.example` key placeholders**. Per the master plan, Phase 1 is primarily *documentation*; actual MCP server installation/config is called out separately and requires manual approval.

**Files to CREATE (Phase 1 only):**
- `docs/ai/mcp/README.md`
- `docs/ai/mcp/FILESYSTEM_MCP.md` — scoped to a single allowlisted corpus path; **no broad FS access**; explicitly *not* the repo root.
- `docs/ai/mcp/GITHUB_MCP.md` — read-only, public-repo doc/release ingestion; least-privilege token scope.
- `docs/ai/mcp/PLAYWRIGHT_MCP.md` — controlled browser fetch for Tier-A docs; no auth flows, no target sites.
- `docs/ai/mcp/FIRECRAWL_MCP.md` — doc scraping; respect robots/TOS; key required.
- `docs/ai/mcp/PERPLEXITY_MCP.md` — research lookups; key required; outputs are *evidence, not commands*.
- `docs/ai/mcp/MCP_SECURITY_MODEL.md` — prompt-injection stance (all external MCP content untrusted), content-vs-instruction separation, no-secrets rule.
- `docs/ai/mcp/MCP_MANUAL_APPROVALS.md` — the list of MCPs that require explicit human enable + why.
- `scripts/ai/check_mcp_prereqs.sh` — checks node/npx availability, prints what's missing; **no installs, no network secrets**.
- `scripts/ai/mcp_smoke_tests.sh` — documented/runnable smoke checks (e.g., Playwright fetch of one public doc); guarded, opt-in.

**Files to MODIFY (Phase 1 only):**
- `.env.example` — **add commented placeholders only**: `GITHUB_TOKEN=`, `FIRECRAWL_API_KEY=`, `PERPLEXITY_API_KEY=`. (Generator `scripts/_gen_env_example.py` exists — confirm whether `.env.example` is generated; if so, modify the generator's source-of-truth instead. **Currently UNVERIFIED because `.env*`/generator internals are permission-blocked** — resolve at Phase 1 start.)
- `.mcp.json` — **OPTIONAL and only if approved**: add Filesystem/Playwright entries with `autoStart: false`. **Default Phase-1 stance: document only, do not edit `.mcp.json`.**

**Explicitly NOT in Phase 1:** no real secrets committed; no broad filesystem MCP; no GitHub write scope; no scraping runs against provider/customer sites; no changes to `apps/`, `scanner/`, `worker/` runtime code.

**Phase 1 stop report must state:** what was *documented* vs *installed*; which MCPs need manual approval; which need keys; what must not be used yet.

---

## 6) Required manual approvals (human-in-the-loop, by phase)

- **Phase 1:** enabling any MCP server in the client; issuing a least-privilege `GITHUB_TOKEN`; obtaining `FIRECRAWL_API_KEY`, `PERPLEXITY_API_KEY`; approving any `.mcp.json` edit.
- **Phase 2:** approving which sources are licensed/ToS-permitted to ingest (Tier D/E especially); confirming retention classes.
- **Phase 4:** decision to reuse `ruvector.db`/claude-flow vector tooling vs. stand up Qdrant/LightRAG (infra + possible new container).
- **Phase 5:** threat-feed API keys (OTX/AbuseIPDB/VirusTotal — VT key state UNVERIFIED) + per-feed license/TOS sign-off; confirmation that ingestion does not duplicate existing runtime TI clients.
- **Phase 8:** sign-off that enrichment stays *suggest-only* (no auto-suppress) before any code touches `apps/api`.
- **Phase 10:** authorization/permission policy + site list before *any* scan beyond owned assets.
- **Cross-cutting:** any change to `apps/`, `scanner/`, `worker/`, or `.mcp.json`.

---

## 7) Required API keys (grounded; placeholders only until approved)

| Key | Needed for | In repo today? |
|-----|-----------|----------------|
| `GITHUB_TOKEN` (read-only) | GitHub MCP doc/release ingestion | **Not in `config.py`**; `.env.example` UNVERIFIED |
| `FIRECRAWL_API_KEY` | Firecrawl MCP | Not found |
| `PERPLEXITY_API_KEY` | Perplexity MCP | Not found |
| `OTX_API_KEY`, `ABUSEIPDB_API_KEY` | Phase 5 feeds | Not found in `config.py` |
| `VIRUSTOTAL_API_KEY` | Phase 5 / existing `virustotal_client.py` | Client exists; **key config UNVERIFIED** (may be read from env directly) |
| `ANTHROPIC_API_KEY` | already used (`WEBHOUND_AI_ENABLED`) | **Exists in `config.py`** — reuse, do not duplicate |

No key is created or stored in Phase 0. URLHaus/ThreatFox/OpenPhish are typically keyless but **TOS/rate-limit UNVERIFIED** — confirm per feed in Phase 5.

---

## 8) Files to create (by phase; Phase 1 is exhaustive above)

- **Phase 1:** `docs/ai/mcp/*` (8 docs), `scripts/ai/{check_mcp_prereqs.sh, mcp_smoke_tests.sh}`.
- **Phase 2:** `corpus/{raw/{docs,repos,papers,feeds,internal},normalized/{docs,repos,papers,feeds},graph,manifests,logs}/`, `corpus/manifest.jsonl`, `docs/ai/corpus/*` (7 docs).
- **Phase 3:** `knowledge/**` tree + per-folder `README.md` + starter FP catalog (the 10 known WebHound FPs).
- **Phase 4:** `docs/ai/{RAG_ARCHITECTURE,LIGHTRAG_SETUP,QDRANT_SETUP,OBSIDIAN_VAULT_PLAN,CLAUDE_MEMORY_POLICY,GRAPH_SCHEMA}.md`, `scripts/ai/{setup_qdrant.sh,setup_lightrag.sh,ingest_sample.py,query_knowledge.py,export_memory_summary.py}`.
- **Phases 5–11:** ingestion scripts, `prompts/*`, `datasets/*`, `apps/api/services/knowledge_enrichment/*`, `audits/*`, `benchmarks/*`, `dashboards/*` (each gated).

**Phase 0 creates exactly ONE file: this document.**

---

## 9) Files to modify

- **Phase 0:** none.
- **Phase 1:** `.env.example` (commented placeholders) — and ONLY IF approved, `.mcp.json` (`autoStart:false` entries). Possibly `scripts/_gen_env_example.py` if `.env.example` is generated (UNVERIFIED).
- **Phase 8 (much later, gated):** thin, additive integration at `apps/api/services/` against the `FindingRecord` shape and existing `wade_correlation.py` — **suggest-only**, no scoring changes.
- **No modifications** to scanner engines, worker, or DB schema are planned before their own approved phases.

---

## 10) Risks

1. **Duplication of existing systems** (TI, WADE, graph, benchmarks). Mitigation: §2 inventory; reuse, don't rebuild.
2. **Scope/altitude creep** — the plan is large; each phase must stay a doc/scaffold unless approved.
3. **Prompt injection via ingested content** — fetched docs/READMEs/feeds are untrusted evidence. Mitigation: provenance stamping + content-vs-instruction separation (Phase 1 security model, Phase 2 policy).
4. **Secrets/PII leakage into corpus** — Mitigation: reuse `telemetry/redaction`, never ingest `.env`/customer scans/tokens; `pii_risk_class`/`retention_class` in manifest.
5. **License/ToS violations** ingesting Tier D/E sources — Mitigation: per-source license field + manual approval gate.
6. **No CI** to enforce governance — Mitigation: note as a gap; consider a minimal CI in a later phase (not assumed).
7. **`.env*` permission-blocked here** → key inventory uncertainty. Mitigation: resolve at Phase 1 start with the operator.
8. **Vector-store ambiguity** (`ruvector.db` vs new Qdrant/LightRAG) — Mitigation: explicit Phase 4 decision, no assumption now.
9. **Provider behavior drift** (e.g., Vercel "Seawall"/firewall) — Mitigation: provider remediation uses official provider docs + the merged registry as ground truth; mark unknowns.
10. **Windows/WSL toolchain friction** (Docker engine was unresponsive earlier; bash-in-PowerShell quirks) — Mitigation: scripts must be cross-platform-aware or documented as WSL-only.

---

## 11) Rollback plan

- All early phases (1–7, 9–11) are **additive, isolated new directories** + docs. Rollback = delete the new tree(s); zero runtime impact because nothing is wired in.
- Phase 1 `.env.example` change is a comment-only addition → revert the diff.
- Phase 4 infra (if Qdrant/LightRAG containers approved) → tear down container(s); data lives in new `corpus/`/volumes, removable.
- Phase 8 is the only phase touching `apps/api`; it is additive + suggest-only + behind tests, and revertible by removing the new `knowledge_enrichment/` module and its call sites. **No DB migrations are planned in the additive phases**; any future migration gets its own approval + downgrade.
- Nothing is committed/pushed without explicit approval, so rollback before commit is just discarding untracked files.

---

## 12) Test plan

- **Phase 1:** assert docs exist; assert no real secrets present; assert FS boundary documented; Playwright smoke documented/runnable; manual-approval MCP list present; **no prod code modified**.
- **Phase 2:** manifest schema validates; sample records round-trip; provenance/hash fields enforced; PII/retention classes required.
- **Phase 4:** sample ingest → retrievable; graph edges build on fixtures; memory-export emits summaries+pointers only (no raw docs).
- **Phase 5:** parse sample URLHaus/ThreatFox/OpenPhish/OTX payloads; normalize to the indicator schema; reject invalid; dedupe; preserve attribution; enforce TTL; **no keys in logs**; `--dry-run` works; **no wiring into prod findings**.
- **Phase 7:** inert fixtures load; goldens carry expected finding-type/severity/confidence/FP-class.
- **Phase 8:** enrichment is deterministic for fixtures; CSP/JS/RSC-FP/third-party/provider cases; no secrets surfaced; **no live scoring change**.
- **Harness reuse:** extend existing `scanner/validation/` + `pytest` rather than a parallel framework. Honor established anti-hang patterns (`timeout`, `.venv-api`, `PYTHONPATH=scanner`, `-p no:cacheprovider`). **No CI exists** → tests run locally until a CI phase is approved.

---

## 13) Stop points

After **every** phase, STOP and report: what was created (docs vs scaffold vs code), what needs manual approval, what needs keys, what must not be used yet, and the proposed next phase. **No phase auto-starts the next.** Phase 0 stops here.

---

## 14) Open questions (must be resolved before the relevant phase)

1. **`.env.example` access** — it's permission-blocked here. Is it hand-maintained or generated by `scripts/_gen_env_example.py`? (Phase 1)
2. **Vector store** — reuse `ruvector.db`/claude-flow vector tooling, or stand up Qdrant + LightRAG? (Phase 4)
3. **Existing TI overlap** — confirm which feeds already have live clients (URLHaus ✅, VirusTotal ✅; ThreatFox/OpenPhish/OTX/AbuseIPDB UNVERIFIED) so Phase 5 augments rather than duplicates. (Phase 5)
4. **`WEBHOUND_AI_ENABLED` relationship** — should the knowledge layer's Claude usage gate on this existing flag/key? (Phase 4/8)
5. **Obsidian vault location** — inside repo (committed) or external operator vault? Licensing of curated third-party content? (Phase 4)
6. **CI** — is introducing minimal CI (GitHub Actions) in scope for governance, given none exists today? (cross-cutting)
7. **Provider doc licensing** — may we mirror provider KB text into `provider-docs/`, or only link + summarize? (Phase 2/3)
8. **`packages/` workspace wiring** — no root `package.json` workspaces field found; confirm monorepo tooling before adding any Node-side knowledge tooling. (as needed)
9. **Mass-scan authorization** — the 6-stage campaign needs a real written permission/site policy before Phase 10. (Phase 10)
10. **Memory backend** — claude-flow `CLAUDE_FLOW_MEMORY_BACKEND=hybrid` already exists; how does "Claude memory summaries" relate to it? (Phase 4)

---

## 15) Recommendation for Phase 1

**Proceed to Phase 1 as documentation-first**, exactly as scoped in §5: create `docs/ai/mcp/*` + `scripts/ai/{check_mcp_prereqs,mcp_smoke_tests}.sh` + commented `.env.example` placeholders, and **do not** edit `.mcp.json` or install any MCP server without a separate explicit approval. Before writing, resolve Open Questions **#1 (`.env.example` source-of-truth)** and confirm the least-privilege intent for the GitHub token.

Rationale grounded in findings: the MCP foundation is genuinely greenfield (only claude-flow is configured), it is the lowest-risk starting point (docs + guarded scripts, zero runtime/DB impact, trivial rollback), and it establishes the prompt-injection/least-privilege security model that every later ingestion phase depends on. It also lets us reconcile early with the **existing** AI path (`WEBHOUND_AI_ENABLED`/`anthropic_api_key`) and the **existing** threat-intel/WADE/graph substrate so subsequent phases extend rather than duplicate.

**STOP — awaiting explicit approval (with further detail) before starting Phase 1.**
