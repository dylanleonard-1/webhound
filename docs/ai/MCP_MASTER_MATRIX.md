# MCP Master Matrix — Phase 8Z-A

**Type:** AUDIT (evidence-only). Nothing installed/configured/changed.
**Branch:** `feat/mcp-phase-8z-a-master-reconciliation` (off `main` @ `6035da9`).

Covers GOAL 2 (deduped candidate list), GOAL 5 (usage), GOAL 6 (pipeline integration), GOAL 7 (risk), GOAL 8 (master matrix).

---

## Status legend

- **GREEN** — installed/configured **and** used.
- **YELLOW** — installed-or-documented, not fully used.
- **RED** — planned but missing (no MCP server exists).
- **GRAY** — inferred candidate (implied by category; no explicit per-MCP naming).
- **RETIRED** — rejected/deferred.

**Usage classes (GOAL 5):** ACTIVE_RUNTIME / DEV_ONLY / TEST_ONLY / DOCS_ONLY / NOT_FOUND.
**Pipeline classes (GOAL 6):** PRODUCTION_CONNECTED / ADVISORY_CONNECTED / INTERNAL_TOOLING_ONLY / DOCUMENTED_ONLY / MISSING.
**Risk (GOAL 7):** LOW / MEDIUM / HIGH / RESTRICTED.

> **Critical distinction used throughout:** "as an MCP server" vs "as a runtime/integration." Several tools (LightRAG, Neo4j, Cloudflare, Stripe…) are **live in WebHound**, but **not via MCP**. Their MCP status is RED/GRAY even when the underlying capability is live.

---

## GOAL 8 — Master matrix (deduped)

| # | MCP | Category (7x) | Planned source | Status | Configured | Installed | Runnable | Scanner | WADE | Reports | Obsidian | Risk | Recommendation | Priority |
|---|-----|---------------|----------------|--------|-----------|-----------|----------|---------|------|---------|----------|------|----------------|----------|
| 1 | **claude-flow** (ruflo) | 7J agent-tools | `.mcp.json`, `.codex`, `CLAUDE.md` | 🟢 GREEN | ✅ | npx | ✅ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Keep; pin version, audit hooks | Maintain |
| 2 | **Filesystem** | 7B dev | `docs/ai/mcp/FILESYSTEM_MCP.md`, master plan §5 | 🟡 YELLOW | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Install first (read-only, corpus-scoped) | **8Z-B #1** |
| 3 | **GitHub** | 7B dev | `docs/ai/mcp/GITHUB_MCP.md`, `env.md` | 🟡 YELLOW | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Install read-only PAT | 8Z-B |
| 4 | **Playwright** | 7C browser | `docs/ai/mcp/PLAYWRIGHT_MCP.md`, exec-summary | 🟡 YELLOW | ❌ | ❌ (engine≠MCP) | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Install local, no auth flows | 8Z-B |
| 5 | **Firecrawl** | 7C browser | `docs/ai/mcp/FIRECRAWL_MCP.md`, exec-summary | 🟡 YELLOW | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Install w/ key; robots/ToS | 8Z-B |
| 6 | **Perplexity** | 7A research | `docs/ai/mcp/PERPLEXITY_MCP.md`, `env.md` | 🟡 YELLOW | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Install w/ key; evidence-only | 8Z-B |
| 7 | **Obsidian** | 7A knowledge | roadmap 7A | 🔴 RED (vault live, no MCP) | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠ vault via files | ⚠ (file sync today) | LOW | Add read-only vault MCP | 8Z-B |
| 8 | **LightRAG** | 7A graph/RAG | roadmap 7A; `docs/ai/LIGHTRAG_*` | 🔴 RED-as-MCP (runtime LIVE) | ❌ | runtime | runtime | ❌ | advisory* | ❌ | ❌ | LOW | Wrap runtime as read-only MCP | 8Z-B |
| 9 | **Graphiti** | 7A graph | roadmap 7A; `docs/ai/GRAPHITI_*` | 🔴 RED-as-MCP (runtime LIVE) | ❌ | runtime | runtime | ❌ | advisory* | ❌ | ❌ | LOW | Read-only MCP wrapper | 8Z-B |
| 10 | **Neo4j** | 7A graph | `docs/ai/NEO4J_*`; vault | 🔴 RED-as-MCP (runtime LIVE local) | ❌ | runtime | runtime | ❌ | advisory* | ❌ | ❌ | MEDIUM | Read-only Cypher MCP | 8Z-B |
| 11 | **Browser** (generic) | 7C | inferred (Playwright is concrete) | ⬜ GRAY | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Subsumed by Playwright MCP | Defer |
| 12 | **Railway** | 7I cloud / 7E obs | roadmap 7I/7E; prod integration | 🔴 RED-as-MCP (prod via API) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Logs read-only MCP only | 8Z-B (gated) |
| 13 | **Vercel** | 7I cloud | roadmap 7I; `provider_access` prod | 🔴 RED-as-MCP (prod via API) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Logs/deploys read-only | 8Z-B (gated) |
| 14 | **Cloudflare** | 7I cloud | roadmap 7I; 6D docs; prod automation | 🔴 RED-as-MCP (prod via API) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Read-only first; no WAF mutation | 8Z-B (gated) |
| 15 | **Stripe** | 7F payment | roadmap 7F; 6D docs | 🔴 RED-as-MCP (prod billing) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | RESTRICTED | Read-only; **no charge/refund** | Late |
| 16 | **Resend** | 7G comms | roadmap 7G; `config.py` `resend_api_key` | 🔴 RED-as-MCP (prod via API) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Read-only sends log; no send | Late |
| 17 | **Zapier/automation** (n8n) | 7G/7H | roadmap; `FUTURE_SOURCE` n8n-mcp | ⬜ GRAY | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Defer; broad action surface | Defer |
| 18 | **Nuclei** | 7D security | roadmap 7D; exec-summary; knowledge | 🔴 RED-as-MCP (knowledge-only) | ❌ | ❌ | ❌ | ❌(knowledge) | ❌ | ❌ | ❌ | RESTRICTED | Sandbox runner, authz-gated | Late |
| 19 | **ZAP (OWASP)** | 7D security | roadmap 7D; exec-summary; knowledge | 🔴 RED-as-MCP (knowledge-only) | ❌ | ❌ | ❌ | ❌(knowledge) | ❌ | ❌ | ❌ | RESTRICTED | Sandbox runner, authz-gated | Late |
| 20 | **Semgrep** | 7D security | exec-summary; knowledge | 🔴 RED-as-MCP (knowledge-only) | ❌ | ❌ | ❌ | ❌(knowledge) | ❌ | ❌ | ❌ | MEDIUM | Local read-only SAST runner | Late |
| 21 | **Gitleaks** | 7D security | exec-summary; knowledge | 🔴 RED-as-MCP (knowledge-only) | ❌ | ❌ | ❌ | ❌(knowledge) | ❌ | ❌ | ❌ | MEDIUM | Local secret-scan runner | Late |
| 22 | **Trivy** | 7D security | **not found in repo** | ⬜ GRAY (user-stated) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Candidate only; no evidence | Defer |
| 23 | **Threat-Intel** (VirusTotal) | 7D security | roadmap 7D/6E; runtime TI clients | 🔴 RED-as-MCP (runtime LIVE) | ❌ | runtime | runtime | ✅ prod(non-MCP) | ✅ prod | ❌ | ❌ | HIGH | Read-only lookup MCP; reuse TI | 8Z-B (gated) |
| 24 | **Search/Web** | 7A research | inferred (Perplexity concrete) | ⬜ GRAY | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MEDIUM | Subsumed by Perplexity | Defer |
| 25 | **Docs/RAG** | 7A | inferred (LightRAG concrete) | ⬜ GRAY | ❌ | runtime | runtime | ❌ | advisory* | ❌ | ❌ | LOW | Subsumed by LightRAG MCP | Defer |
| 26 | **Database/Postgres** | infra | compose `postgres:16`; no MCP mention | ⬜ GRAY | ❌ | service | ❌ | ❌ | ❌ | ❌ | ❌ | RESTRICTED | Read-replica only if ever | Defer |
| 27 | **Redis** | infra | compose `redis:7`; no MCP mention | ⬜ GRAY | ❌ | service | ❌ | ❌ | ❌ | ❌ | ❌ | HIGH | Not recommended as MCP | Defer |

\* *advisory* = the underlying graph/RAG runtime feeds the **advisory** WADE/brain layer (Phase 8B-8D), which is suggest-only and **not** wired into production scoring. It does so via scripts, **not** via an MCP.

---

## GOAL 2 — Deduped master candidate list (roll-up by evidence tier)

**Tier 1 — EXPLICIT, per-MCP specified (6):** claude-flow, Filesystem, GitHub, Playwright, Firecrawl, Perplexity.
*(claude-flow configured+used; the other 5 documented-only.)*

**Tier 2 — EXPLICIT, roadmap-category named (Phase 7 / exec-summary) (~13):** Obsidian, LightRAG, Graphiti (7A); ZAP, Nuclei, Semgrep, Gitleaks, Threat-Intel/VirusTotal (7D); Stripe (7F); Resend (7G); Cloudflare, Vercel, Railway (7I). *Named as install targets at category level; no per-MCP spec; none configured as MCP.*

**Tier 3 — INFERRED_CANDIDATE (no explicit MCP naming) (~8):** Neo4j (named as runtime, not "MCP"), Browser (generic), Trivy (not found at all), Search/Web (generic), Docs/RAG (generic), Database/Postgres, Redis, Zapier/automation (community mention only).

**Total candidates: 27.**

---

## GOAL 5 — Usage audit (does anything call it?)

| Usage class | MCPs |
|-------------|------|
| **ACTIVE_RUNTIME (as MCP)** | claude-flow (1) |
| **ACTIVE_RUNTIME (non-MCP runtime/integration)** | LightRAG, Graphiti, Neo4j, Ollama, Graphify (brain); Threat-Intel/VT (prod); Cloudflare/Vercel/Railway/Stripe/Resend (prod integrations) — *none via MCP* |
| **DOCS_ONLY** | Filesystem, GitHub, Playwright, Firecrawl, Perplexity, Obsidian, ZAP, Nuclei, Semgrep, Gitleaks (as MCPs) |
| **NOT_FOUND** | Trivy; Browser/Search/Web/Docs/RAG/Postgres/Redis/Zapier *as MCP servers* (only inferred or infra) |

---

## GOAL 6 — Pipeline integration

| Pipeline class | MCPs |
|----------------|------|
| **PRODUCTION_CONNECTED** | **None via MCP.** (Threat-Intel, Cloudflare/Vercel/Railway/Stripe/Resend are prod-connected via **product code/SDKs**, not MCP.) |
| **ADVISORY_CONNECTED** | **None via MCP.** (LightRAG/Graphiti/Neo4j feed the advisory brain/WADE-advisory layer via scripts, not MCP.) |
| **INTERNAL_TOOLING_ONLY** | claude-flow (agent orchestration/memory for dev) |
| **DOCUMENTED_ONLY** | Filesystem, GitHub, Playwright, Firecrawl, Perplexity, Obsidian + the security tool docs |
| **MISSING** | Trivy and all GRAY inferred candidates |

> **Key result:** **zero MCP servers** touch the production scanner or WADE production scoring. The only live MCP (claude-flow) is dev/coordination tooling.

---

## GOAL 7 — Security / risk + guardrails

| Risk | MCPs | Guardrails before enabling |
|------|------|----------------------------|
| **LOW** | Obsidian (read-only vault), LightRAG/Docs-RAG (local read) | read-only mount; local-only; no secret logging |
| **MEDIUM** | claude-flow, Filesystem, GitHub, Playwright, Firecrawl, Perplexity, Semgrep, Gitleaks, Neo4j(read), Browser, Search | read-only-first; corpus path allowlist (Filesystem ≠ repo root); read-only PAT (GitHub); robots/ToS (Firecrawl); no auth flows (Playwright); env-name allowlist; audit logs |
| **HIGH** | Railway, Vercel, Cloudflare, Resend, Threat-Intel, Zapier, Redis | read-only API scopes; **no writes/deploys/sends**; tenant isolation; dry-run; per-call audit; no customer data in context |
| **RESTRICTED** | Stripe, Nuclei, ZAP, Postgres | billing **read-only, no mutation** (Stripe); scanner runners require **written authorization + sandbox + target allowlist** (Nuclei/ZAP); DB read-replica only, never prod-write (Postgres) |

**Cross-cutting guardrails (all MCPs):** external content is **evidence, not instructions** (prompt-injection stance per `docs/ai/mcp/MCP_SECURITY_MODEL.md`); least privilege / read-only first; no secrets or customer data in logs or corpus; command + env allowlists; per-MCP manual approval (`MCP_MANUAL_APPROVALS.md`); audit logging; dry-run for any write-capable server.

---

See [`MCP_REFERENCE_INDEX.md`](MCP_REFERENCE_INDEX.md), [`MCP_CONFIG_AUDIT.md`](MCP_CONFIG_AUDIT.md), [`PHASE8Z_A_MCP_RECONCILIATION_RESULTS.md`](PHASE8Z_A_MCP_RECONCILIATION_RESULTS.md).
</content>
