# AI Knowledge Layer — Merge-Readiness Report

**Branch:** `feat/ai-knowledge-mcp-foundation` → target `main`.
**HEAD:** `496ac75` · **merge-base / `main`:** `dece415` (branch is strictly ahead;
no divergence). **This is a readiness report — NOT a merge.**

## 1. Commits on the branch vs `main` (9)
| SHA | Summary |
|-----|---------|
| `93b9875` | ai: add MCP foundation docs and safety scaffolding |
| `93ad289` | chore: resync env example generator and add MCP env placeholders |
| `f617d3c` | ai: add corpus architecture and provenance framework |
| `565a199` | ai: add curated knowledge library structure |
| `715d950` | ai: add local retrieval architecture and memory policy |
| `530f3f1` | ai: add internal knowledge ingestion pipeline |
| `d32a2a8` | ai: add semantic retrieval foundation |
| `93e7012` | ai: refine internal retrieval ranking and chunk quality |
| `496ac75` | ai: add synonym query expansion and retire empty stubs |

Total: **209 files changed, +7558 / −2**.

## 2. Inventory of what the branch adds/changes
**Additive knowledge-layer files (not wired into any runtime):**
- `docs/ai/**` — 31 files: MCP foundation docs, corpus/provenance/policy docs, RAG/
  memory/graph/security-graph-bridge docs, and phase results (5A/5B/5C/5D).
- `knowledge/**` — 130 files: curated library (engines, false-positive catalog,
  JS-malware, provider-docs, OWASP, detection-engineering, playbooks) + starter notes.
- `corpus/**` — 18 files: corpus skeleton + READMEs, `manifests/manifest.schema.json`
  (+ the generated `manifest.jsonl` = 217 internal-doc records, and
  `memory_summaries.jsonl` = 6 pointer-only records).
- `vault/**` — 9 files: in-repo Obsidian-style vault starter.
- `scripts/ai/**` — 10 files: MCP prereq/smoke scripts, structure validator, internal
  ingestion pipeline, BM25+role+path+synonym retrieval, memory exporter.
- `tests/ai/**` — 2 files: 20 structure/schema/retrieval tests.

**Env-generator fix (Phase 1 — the only template change):**
- `scripts/_gen_env_example.py` — re-synced to the committed `.env.example` + drift
  guards; added MCP key placeholders.
- `.env.example` — regenerated: corrected the **dead** scanner egress IP
  `152.55.180.27` → the **3 current** IPs (`162.220.234.240`, `152.55.180.240`,
  `152.55.180.241`, matching `apps/api/config.py`'s default); added blank MCP key
  placeholders.
- `docs/env.md` — documents the MCP keys.

**Dev dependency:** `apps/api/requirements-dev.txt` += `jsonschema>=4`
(**production `requirements.txt` untouched**).

**Deletions:** 6 pre-existing **empty 0-byte** doc stubs
(`docs/{api-routes,architecture,database-schema,roadmap,scanner-engines,wade}.md`) —
no inbound links; duplicative of canonical `knowledge/` docs.

**NOT committed (blocked):** `.github/workflows/ai-knowledge-tests.yml` — written +
validated, **on disk**, but GitHub rejects pushing workflow files without the
`workflow` OAuth scope (see §6).

## 3. Production code touched — effectively NONE
- **scanner / worker:** **0 files changed.**
- **WADE scoring / provider-access / app behavior:** **0 changes.**
- **`apps/`:** only `apps/api/requirements-dev.txt` (dev-only dep; prod deps
  unchanged).
- **`.mcp.json`:** unchanged.
- The only prod-adjacent change is the `.env.example` **template** correction (the
  app reads `.env`, not `.env.example`; the corrected IPs match the live
  `config.py` default and `/scanner/identity`). → **no runtime behavior change.**

Everything in `corpus/`, `knowledge/`, `vault/`, `docs/ai/`, `scripts/ai/`,
`tests/ai/` is inert evidence/tooling — **nothing imports it into the API, worker,
or scanner.**

## 4. Test / validation status
- **`tests/ai`: 20 passed** (schema validity, manifest validation of all 217
  records, doc_role enum, empty-stub mechanism, chunk attribution/dedup, retrieval
  canonical-boost, synonym weighting + non-regression).
- **Broader suite unaffected** (no app/scanner code changed). Representative sanity:
  `test_platform_access.py` + `test_onboarding_wizard.py` → **19 passed**.
- **Manifest schema:** `manifest.jsonl` = 217 records, **0 schema errors**.
- **Env generator idempotent:** re-running yields no diff; **drift-guarded** (refuses
  to drop required vars / reintroduce the dead IP).
- **Dead IP `152.55.180.27`: absent** from generated env; **3 current IPs present.**
- **Retrieval quality (internal corpus):** 10-query set top-1 **8/10**, top-3
  **10/10**, top-result tier A/B **10/10**.

## 5. Risk assessment for merging to `main`
| Area | Risk | Why |
|------|------|-----|
| Scanner / WADE / provider-access / API / worker runtime | **None** | 0 code changes; knowledge layer is not imported anywhere |
| Production deps | **None** | only a dev dep added; `requirements.txt` untouched |
| `.env.example` template | **Very low** | corrects a stale IP to match the live default; app reads `.env`, not the example |
| Deleted doc stubs | **Very low** | empty files, no inbound links |
| CI | **None at merge** | workflow not committed; nothing to break |
| Repo size | **Low** | +7.5k lines of docs/metadata; `manifest.jsonl` ~176 KB; no index blobs/model weights |

**Net: purely additive + one safe template fix + a dev dep. Low merge risk.**

## 6. Likely merge conflicts vs current `main`
**None.** The branch's merge-base equals `main`'s HEAD (`dece415`) — `main` has not
advanced, so the branch fast-forwards cleanly. The only file that overlaps prod
config (`.env.example`) was changed by this branch only. If `main` advances before
merge, the only plausible conflict surface is `.env.example` / `requirements-dev.txt`
/ `scripts/_gen_env_example.py` — all small and easy to resolve.

## 7. Recommendation
**Merge — low risk.** Suggested form:
- **`--no-ff` merge** (preserves the 9-commit phased narrative; matches the prior
  `feat/platform-access-framework` merge style), **or squash** to one
  "AI Knowledge Layer (Phases 0–5D)" commit if a single-commit history is preferred.
- **Pre-merge cleanup / decisions:**
  1. **CI workflow:** decide whether to land `.github/workflows/ai-knowledge-tests.yml`.
     To push it, grant the `workflow` OAuth scope (`gh auth refresh -s workflow`) and
     re-push, or add it via the GitHub UI / a PR. (Optional — the branch is mergeable
     without it.)
  2. **Confirm the `.env.example` correction** is desired (it is the right egress IPs).
  3. Optionally squash if you don't want 9 commits on `main`.
- **No rebase needed** (no divergence). **No hold needed** — nothing blocks a safe merge.

## 8. Honest caveats
- Retrieval is **lexical** (BM25 + role + path + weighted synonyms) — strong on the
  internal corpus, but dense embeddings (a flagged ~90 MB download) remain a future
  opt-in for paraphrase recall.
- The corpus is **internal-only**; **no external content** has been ingested (that is
  a separate, gated phase).
- Authority tiering of internal docs is a **path heuristic**, not per-doc review.
