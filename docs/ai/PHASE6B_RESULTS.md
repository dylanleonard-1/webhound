# Phase 6B — Official Security Repository Ingestion (Results)

**Status:** complete on branch `feat/ai-knowledge-phase-6b-official-repos` (from the
Phase-6A merge `1bb3385`).
**Date:** 2026-06-13.
**Scope:** controlled ingestion of documentation from a fixed allow-list of 10
official/high-authority security & tooling repositories as Tier-C `official_repo`
records. This is **controlled repo ingestion, not blind repo mirroring**.

Phase 6B is **append-only**. The pre-existing 217 manifest records (211 internal +
6 Phase-6A `official_doc`) are **byte-stable** (verified: `head -n 217` SHA-256
`361f2fc7…` unchanged before/after). No internal hashes were recomputed.

---

## Repositories ingested (10)

Each file is pinned to the repo's HEAD commit SHA at fetch time. `source_url` is the
immutable raw-at-commit URL; `version` records the short commit.

| Repo | Pinned commit | License | Doc-md candidates | Kept | Skipped (cap/too-big/excluded) |
|---|---|---|---|---|---|
| `projectdiscovery/nuclei` | `7f6096ee6602` | MIT | 19 | 10 | 9 / 0 / 18 |
| `projectdiscovery/httpx` | `7fd08b7f8da3` | MIT | 1 | 1 | 0 / 0 / 4 |
| `projectdiscovery/katana` | `b4c40e40fd87` | MIT | 3 | 3 | 0 / 0 / 4 |
| `owasp-amass/amass` | `79299dce87b0` | Apache-2.0 | 1 | 1 | 0 / 0 / 1 |
| `gitleaks/gitleaks` | `81fc7f93b7a0` | MIT | 3 | 3 | 0 / 0 / 10 |
| `semgrep/semgrep` | `11dd170b2c60` | LGPL-2.1 | 25 | 10 | 15 / 0 / 12 |
| `modelcontextprotocol/servers` | `275175cda17c` | CC-BY-4.0 | 18 | 12 | 6 / 0 / 4 |
| `microsoft/playwright-mcp` | `b301c372ec74` | Apache-2.0 | 4 | 4 | 0 / 0 / 2 |
| `github/github-mcp-server` | `34227037fc48` | MIT | 31 | 8 | 23 / 0 / 13 |
| `HKUDS/LightRAG` | `bbf47785738b` | MIT | 39 | 10 | 29 / 0 / 13 |

**Totals:** 61 files ingested → **61 `official_repo` records** and **552 chunks**.
Manifest grew 217 → **278**. (Exact per-file pins are committed in
`corpus/normalized/repos/ingest_summary.json`.)

> **Localized-doc exclusion:** the locale filter excludes non-English docs by a
> `.`/`_`/`-`-separated locale token (e.g. `README.zh-CN.md`, `README-zh.md`).
>
> **Non-knowledge exclusion:** governance/metadata/agent-instruction files are
> excluded by basename — `LICENSE`, `CONTRIBUTING`, `CODE_OF_CONDUCT`, `THANKS`,
> `AUTHORS`, `USERS`, `SUPPORT`, `CODEOWNERS`, `CHANGELOG`, `METRICS`,
> `*third-party-licenses*`, and **`CLAUDE.md`** (external agent instructions are
> not knowledge; kept out per the prompt-injection policy — external content is
> evidence, never instructions). `SECURITY.md` and genuine docs are kept.

### Exact repo URLs

- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/owasp-amass/amass
- https://github.com/gitleaks/gitleaks
- https://github.com/semgrep/semgrep
- https://github.com/modelcontextprotocol/servers
- https://github.com/microsoft/playwright-mcp
- https://github.com/github/github-mcp-server
- https://github.com/HKUDS/LightRAG

---

## What was ingested vs. skipped (per repo)

**Ingested (per file):** documentation-bearing markdown only — `README.md`,
`docs/**`, top-level guides, examples/usage docs, security docs, and release notes
written as markdown. One normalized text artifact + manifest record per file.

**Skipped (always excluded):** source trees (`.go/.py/.js/.ts/...`), `node_modules`,
`vendor`, `dist`, `build`, `bin`, `.git`, `.github/`, test fixtures/data/snapshots,
locales/translations/i18n, datasets, binaries, generated files, and any file
> 200 KB. Non-English localized READMEs (`README.zh-CN.md`, etc.) are skipped.
Per-repo file caps apply (8–12); files beyond the cap are reported in the
"Skipped (cap)" column above and were **not** ingested.

**Notably capped repos:** `lightrag` (39 candidates → 10), `github-mcp-server`
(31 → 8), `semgrep` (25 → 10), `nuclei` (19 → 10). The cap selects the highest-signal
docs first (root `README`, then `SECURITY`, then `docs/**` by depth).

**No raw repo clone or source tree was committed.** Clones/fetches were ephemeral
under the OS temp dir (`/tmp/webhound_repo_raw`, never in git). Only normalized text
+ chunks + manifest metadata are committed. (Enforced by
`tests/ai/test_official_repos.py::test_no_raw_repo_clone_committed`.)

---

## Manifest record shape

Every `official_repo` record carries: repo owner/name (`source_name`), tool name
(`product_or_provider`), pinned commit (`version`), raw-at-commit URL with the file
path (`source_url`), file path in `title` + `entities`, `content_hash`,
`license_terms`, `topic_tags`, `first_ingested`, `verification_status=verified`,
`related_docs`. `authority_tier=C`, `source_type=official_repo`,
`doc_role` ∈ {`engine_note` (scanner tools), `canonical_note` (MCP/LightRAG)}.

A new enum value `official_repo` was appended to `source_type` in
`corpus/manifests/manifest.schema.json` (append-only, backward-compatible; all 278
records validate).

---

## Topic tags used

`github-repo`, `web-security`, `scanner-engine`, `crawling`, `url-discovery`,
`http-probing`, `nuclei-templates`, `vulnerability-detection`, `static-analysis`,
`secrets-detection`, `javascript-security`, `mcp`, `playwright`, `lightrag`,
`detection-engineering`, `benchmarking`, `attack-surface`, `server-tooling`.

---

## Retrieval results (offline, repo discovery)

Repo-level retrieval (`retrieve_repos`) over committed chunks: BM25-style term
overlap with IDF weighting + light plural folding + a topic-tag boost, max-pooled
per repo. **Acceptable = an expected repo appears in top-3.** Result: **10/10
acceptable** (top-1 8/10; the two non-top-1 — HTTP probing, static-analysis — share
generic vocabulary with sibling tools but still surface in top-3).

| # | Query | Top-3 repos | Acceptable |
|---|---|---|---|
| 1 | nuclei-style vulnerability templates | nuclei, gitleaks, mcp-servers | ✅ nuclei |
| 2 | crawling and URL discovery | katana, amass, github-mcp-server | ✅ katana |
| 3 | HTTP probing | mcp-servers, github-mcp-server, httpx | ✅ httpx |
| 4 | attack surface discovery | amass, nuclei, katana | ✅ amass |
| 5 | secret detection | gitleaks, nuclei, semgrep | ✅ gitleaks |
| 6 | static analysis rules | gitleaks, semgrep, lightrag | ✅ semgrep |
| 7 | documents MCP servers | mcp-servers, github-mcp-server, playwright-mcp | ✅ mcp-servers |
| 8 | documents Playwright MCP | playwright-mcp, mcp-servers, github-mcp-server | ✅ playwright-mcp |
| 9 | explains LightRAG | lightrag, mcp-servers | ✅ lightrag |
| 10 | most relevant to scanner engine audits | semgrep, nuclei, lightrag | ✅ (semgrep + nuclei) |

The **internal** retrieval baseline is unchanged by this ingestion:
`semantic_retrieval.py compare` still reports top-1 8/10, top-3 10/10, Tier A/B
10/10 over the internal 10-query set.

> **Internal-index isolation fix:** `ingest_internal_knowledge.py` previously swept
> *all* of `corpus/**` into the internal retrieval index, so the new Tier-C repo
> docs (which the internal classifier tags `corpus/` → Tier-A) briefly displaced a
> real internal note (a `semgrep` README out-ranked the false-positive catalog for
> "what known false positives exist?", dropping the internal top-1 to 7/10). Added a
> one-line exclusion of `corpus/normalized/repos/` from the internal sweep —
> external repo evidence is retrieved via `ingest_official_repos.py`, never as
> internal knowledge. Baseline restored to 8/10. (No internal manifest records were
> rebuilt; the change only affects the in-memory internal index.)

---

## Validation results

- `scripts/ai/validate_knowledge_structure.py` → **10/10 ok**, incl. `.mcp.json`
  unmodified (only `claude-flow` server).
- `pytest tests/ai` → **35 passed** (27 prior + 8 new in `test_official_repos.py`).
- Manifest schema: all **278** records validate (Draft 2020-12).
- Chunk validation: 552 chunks, no orphans, every record has ≥1 chunk.
- Secret scan over committed artifacts (AWS/GitHub/Slack/Google/OpenAI tokens,
  private keys) → **no matches**.
- Internal 217 records byte-stable (`head -n 217` SHA-256 unchanged).
- No scanner / WADE / provider-access changes; `.mcp.json` byte-identical to `main`.
- No raw repo clones / source trees committed.

---

## Licensing notes / concerns

- **MIT** (nuclei, httpx, katana, gitleaks, github-mcp-server, LightRAG) and
  **Apache-2.0** (amass, playwright-mcp) — permissive; attribution recorded via
  `source_name` + `source_url` per record.
- **`owasp-amass/amass`** — GitHub's license API returns `NOASSERTION` because the
  `LICENSE` has a custom copyright header, but the file states **Apache-2.0**;
  recorded as `Apache-2.0` (manual override).
- **`semgrep/semgrep`** — **LGPL-2.1**. We ingest documentation text only (no source
  redistribution); attribution recorded. Worth a maintainer review before any
  downstream redistribution of derived text.
- **`modelcontextprotocol/servers`** — repo is mid-transition **MIT → Apache-2.0**;
  **documentation is CC-BY-4.0**. Since we ingest docs, recorded as `CC-BY-4.0`
  (manual override). Flagged for awareness given the in-flight relicensing.

No secrets, PII, or customer data ingested. External content is stored as plain
evidence text and never executed.

---

## Gaps / issues found

- **amass** and **httpx** expose very little knowledge markdown in-repo (1 doc each
  after governance/license files are excluded); their
  substantive docs live on external doc sites/wikis not covered by this phase.
- Non-markdown, high-value assets were intentionally **not** ingested this phase:
  Nuclei YAML templates + template JSON schema, Semgrep rule YAML, Gitleaks TOML
  config. These are detection-grade knowledge but are data/config, not prose.
- Retrieval is the offline term-overlap + tag-boost smoke retriever (no embeddings,
  per project constraints); good enough for repo discovery, not semantic depth.

---

## Recommendations for Phase 6C

1. **Tool config/templates as structured knowledge** — ingest Nuclei template
   schema + a curated sample of templates, Semgrep rule schema + sample rules, and
   Gitleaks default config, as a distinct `dataset`/`benchmark`-typed tier (separate
   from prose), with strict caps. This is where the highest detection signal lives.
2. **Doc sites** for amass/httpx/katana/semgrep (ProjectDiscovery docs, Semgrep
   registry docs) where in-repo markdown is thin — as Tier-B/C official docs.
3. **Provider firewall docs** (Cloudflare WAF, Vercel, AWS WAF, etc.) — but only once
   matched against the provider-access registry (deferred, not this phase).
4. Revisit `semgrep` (LGPL) and `mcp-servers` (relicensing) license posture before
   any redistribution of derived text.
5. Consider embeddings/LightRAG (currently disallowed) to move repo retrieval from
   term-overlap to semantic — gated on explicit approval.
