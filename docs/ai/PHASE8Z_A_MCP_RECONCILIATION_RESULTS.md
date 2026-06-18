# Phase 8Z-A — MCP Master Reconciliation Results

**Type:** AUDIT (evidence-only). No production behavior changed. `.mcp.json`/scanner/WADE-scoring/provider-access/billing/auth untouched. No installs, no external calls, no secrets, no customer data.
**Branch:** `feat/mcp-phase-8z-a-master-reconciliation` (off `main` @ `6035da9`).
**Precheck:** `main` clean @ `6035da9`; PR #22 (Phase 9B-B) OPEN, CI green; PR #23 (Phase 8X) OPEN, CI green; `.mcp.json` = claude-flow only; Obsidian vault + `docs/ai/` + phase docs confirmed present.
**Companion docs:** [`MCP_REFERENCE_INDEX.md`](MCP_REFERENCE_INDEX.md) · [`MCP_CONFIG_AUDIT.md`](MCP_CONFIG_AUDIT.md) · [`MCP_MASTER_MATRIX.md`](MCP_MASTER_MATRIX.md).

> Note: the context-provided `WEBHOUND_COMPLETE_PROJECT_REFERENCE.md` does **not** exist in the repo. The de-facto master reference is `WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md`. `TOOLING_INVENTORY.md` / `docs/ai/PHASE8X_RESULTS.md` exist only on the **PR #23 branch**, not on `main` (cited as corroboration).

---

## 1. Summary

WebHound's repository configures **exactly one** MCP server — `claude-flow` (`.mcp.json` + `.codex/config.toml`, `autoStart:false`) — used for agent orchestration/memory in development. A **five-MCP foundation** (Filesystem, GitHub, Playwright, Firecrawl, Perplexity) is **documented** under `docs/ai/mcp/` but never installed or configured. Beyond that, an **earlier, broader MCP vision** exists in two user-uploaded planning PDFs (normalized into `corpus/normalized/planning/`): a **Phase-7 "Tool + MCP installation foundation" spanning ten category subphases (7A–7J)** — graph/Obsidian, dev, browser/crawl, security, observability, payment, comms, productivity, cloud, agent-tools. That category plan, expanded to concrete servers, reaches the ~20-MCP scale the user remembers.

The bulk of MCP "hits" in the repo (~95% of 3,457) are **ingested knowledge corpus** — external repos like `modelcontextprotocol/servers`, `playwright-mcp`, `github-mcp-server`, `firecrawl-mcp-server` copied in as DATA — **not** WebHound MCP installs. Several tools often mistaken for MCPs (LightRAG, Graphiti, Neo4j, Ollama, Graphify) are **live local runtimes accessed via scripts/Ollama, not MCP servers**. Likewise Cloudflare/Vercel/Railway/Stripe/Resend/Threat-Intel are **production integrations in product code, not MCPs**.

**Net:** the MCP *ecosystem* is early-stage (1 live server, 5 documented), but the surrounding *capabilities* the MCPs were meant to expose are, in many cases, already live by other means.

---

## 2. Counts

| Metric | Count |
|--------|-------|
| Total MCP candidates (deduped) | **27** |
| Explicitly planned — per-MCP specified | **6** (claude-flow + 5 documented) |
| Explicitly planned — roadmap-category named (Phase 7 / exec-summary) | **~13** |
| Inferred-only candidates | **~8** |
| Configured (`.mcp.json`/`.codex`) | **1** (claude-flow) |
| Installed as a package | **0** |
| Runnable (via `npx`, not vendored) | **1** (claude-flow) |
| Used in production **via MCP** | **0** |
| Used in advisory **via MCP** | **0** |
| Docs-only (as MCP) | **5** documented + ~5 security-tool docs |
| Missing entirely | Trivy + most GRAY inferred |
| Live as **non-MCP** runtime/integration | LightRAG, Graphiti, Neo4j, Ollama, Graphify, Threat-Intel, Cloudflare, Vercel, Railway, Stripe, Resend |

---

## 3. GOAL 9 — Reconciling the "~20 MCP" claim (explicit)

**The user's memory is corroborated, not contradicted — with an important precision.**

**What the evidence shows:**

1. **6 MCPs are explicitly specified per-server:** `claude-flow` (configured+used) and the five documented foundation MCPs (Filesystem, GitHub, Playwright, Firecrawl, Perplexity). This matches the Phase 8X audit's "6 planned, 1 active (17%)."

2. **A ~20-MCP-scale plan DOES exist** — in the uploaded **`WebHound_Master_Tooling_Knowledge_WADE_Roadmap.pdf`** (normalized to `corpus/normalized/planning/master-tooling-wade-roadmap.md`). Its **Phase 7 — "Tool + MCP installation foundation"** enumerates **ten MCP category subphases**:
   - **7A** local knowledge/research — LightRAG, Graphiti, Obsidian (+ Neo4j runtime)
   - **7B** dev MCPs — GitHub, Filesystem
   - **7C** browser/crawl MCPs — Firecrawl, Playwright
   - **7D** security MCPs — ZAP, VirusTotal (+ Nuclei/Semgrep/Gitleaks per exec-summary)
   - **7E** observability — (Railway/Vercel logs)
   - **7F** payment — Stripe
   - **7G** comms — Resend/Slack-class
   - **7H** productivity
   - **7I** cloud — Cloudflare, Vercel, Railway, AWS
   - **7J** Claude Council / agent tools — claude-flow
   Expanding 7A–7J to concrete servers yields **~20+ distinct MCP candidates** — the scale the user recalls.

3. **The number "20" also literally appears** in `WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md` §1 as **"all 20 inspection items"** — but that is a **repo-inspection checklist of 20 items, NOT 20 MCPs.** This is the most likely source of a "20" that got remembered as "20 MCPs."

**Verdict:**
- **Evidence FOUND** for a broad, ~20-scale MCP *vision* → the Phase-7 (7A–7J) roadmap. ✅ The user's claim is substantiated at the **category/vision** level.
- **Evidence NOT found** for **20 individually-specified MCP server specs**. Only **6** were ever distilled to per-MCP detail; the remaining ~14–21 exist as **category-level intentions**, **non-MCP runtimes**, or **product integrations**.
- Per audit policy, **no candidate is dismissed.** All 27 are retained in the matrix; those without explicit per-MCP evidence are marked `INFERRED_CANDIDATE` / roadmap-category and noted *"retained as user-stated / roadmap-stated plan."*

**One-line answer:** *Yes — a ~20-MCP plan exists as the Phase-7 10-category roadmap (7A–7J) from the uploaded master-tooling PDF; but only 6 MCPs are specified per-server and only 1 (claude-flow) is live. The "20" is real as a vision, not as 20 finished specs.*

---

## 4. Top-10 MCP gaps

1. **Filesystem MCP** — documented, not installed (lowest-risk, highest-leverage local win).
2. **Obsidian MCP** — vault is live but only via file sync; no read MCP for the brain.
3. **LightRAG/Graphiti/Neo4j MCP wrappers** — runtimes live, but **no MCP** exposes them to Claude.
4. **GitHub MCP** — no repo/PR context available to the AI layer.
5. **Playwright MCP** — browser engine is prod-opt-in, but no MCP for AI-driven sessions.
6. **Firecrawl MCP** — documented; no live doc-extraction path for the corpus.
7. **Perplexity MCP** — no live CVE/research lookup in advisory.
8. **Threat-Intel MCP** — TI runtime is prod, but not exposed as a read-only MCP lookup.
9. **Cloudflare/Vercel/Railway read-only log MCPs** — prod integrations exist; no safe read MCP surface.
10. **No MCP touches production or advisory pipelines at all** — the structural gap: every live capability reaches the pipeline via product code/scripts, never via MCP.

---

## 5. GOAL 10 — Recommended implementation order (value vs risk) → Phase 8Z-B

**Batch 1 — Safe local, read-only (LOW/MEDIUM):**
1. Filesystem MCP (corpus-path allowlist; **not** repo root)
2. Obsidian MCP (read-only vault)
3. LightRAG / Docs-RAG MCP (local read wrapper over the live runtime)
4. Playwright MCP (local, no auth flows, no target sites)
5. Neo4j read-only MCP (Cypher read; reuse local graph)

**Batch 2 — Read-only external w/ keys (MEDIUM):**
6. GitHub MCP (read-only fine-grained PAT)
7. Firecrawl MCP (key; robots/ToS; doc-scrape only)
8. Perplexity MCP (key; evidence-only output)

**Batch 3 — Infra read-only (HIGH, gated):**
9. Railway logs (read-only) · 10. Vercel logs/deploys (read) · 11. Cloudflare (read-only; **no WAF mutation**)

**Batch 4 — Billing/comms read-only (HIGH/RESTRICTED, gated):**
12. Stripe (**read-only; no charge/refund**) · 13. Resend (read-only sends log; no send)

**Batch 5 — Security-tool runners (RESTRICTED, sandboxed, last):**
14. Semgrep · 15. Gitleaks (local SAST/secret read) → then 16. Nuclei · 17. ZAP (sandbox + **written authorization + target allowlist + dry-run**)

**Deferred / no evidence:** Trivy, generic Browser/Search, Postgres/Redis MCPs, Zapier/automation.

**Order principle:** read-only-first; local before external; never expose production scoring/scanner mutation; each server gated by `MCP_MANUAL_APPROVALS.md` with env-name + command allowlists and audit logging.

---

## 6. Risk notes

- **Prompt injection:** all MCP-fetched content (pages, READMEs, search results, repo data) is **evidence, not instructions** — enforce the `MCP_SECURITY_MODEL.md` content-vs-instruction separation before any external-fetch MCP goes live.
- **Privilege creep:** infra/billing/comms MCPs (Railway/Vercel/Cloudflare/Stripe/Resend) must ship **read-only** with no write/deploy/charge/send capability; tenant isolation; no customer data into model context.
- **Scanner-runner danger:** Nuclei/ZAP MCPs are RESTRICTED — they can attack live targets; require sandbox + written authorization + allowlist + dry-run; never wire into auto-scan without explicit per-engagement sign-off.
- **Runtime ≠ MCP confusion:** keep the matrix's "as MCP" column authoritative; do not let "LightRAG is live" be read as "LightRAG MCP exists."

---

## 7. 8Z-B recommendation

Proceed to **Phase 8Z-B — MCP Safe Installation & Read-Only Integration**: install Batch 1 (Filesystem, Obsidian, LightRAG, Playwright, Neo4j-read) under read-only/least-privilege policies with per-server approval, audit logging, and **no** wiring into production scanner or WADE production scoring. Treat Batches 3–5 as separately-gated later steps. Keep `claude-flow` as-is (pin version, audit hooks).

---

## STATE OF MCP ECOSYSTEM

| Dimension | Value |
|-----------|-------|
| Total candidates | **27** |
| Explicitly planned (per-MCP) | **6** |
| User-stated / roadmap-stated but not per-MCP-specified | **~21** (13 roadmap-category + 8 inferred) |
| Configured | **1** (claude-flow) |
| Installed (package) | **0** |
| Runnable (npx) | **1** |
| Used in production (via MCP) | **0** |
| Used in advisory (via MCP) | **0** |
| Docs-only | **5** foundation (+ ~5 security-tool docs) |
| Missing | Trivy + most inferred |
| Live as non-MCP runtime/integration | **11** (LightRAG, Graphiti, Neo4j, Ollama, Graphify, Threat-Intel, Cloudflare, Vercel, Railway, Stripe, Resend) |
| **MCP-ecosystem completeness** | **~17%** (1 of 6 per-MCP-specified live; ~4% if measured against the full ~27 candidate set) |
| **Recommended next phase** | **Phase 8Z-B — MCP Safe Installation & Read-Only Integration** (Batch 1 first) |

*Audit complete. No production behavior changed; `.mcp.json` unchanged; only audit docs added.*
</content>
