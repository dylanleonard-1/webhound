# Phase 6C — Detection Engineering Repository Ingestion (Results)

**Status:** complete on branch `feat/ai-knowledge-phase-6c-detection-engineering` (from
Phase-6B merge `f398ff5`).
**Date:** 2026-06-13.
**Scope:** controlled ingestion of detection-methodology documentation from 8 approved
detection-engineering repositories (Tier-C `detection_repo`), 2 planning references
(Tier-B `planning_reference`), and 36 authored knowledge notes (Tier-B `internal_doc`).
**Knowledge purpose:** build the Detection Engineering Knowledge Base that will inform
Phase 8 (WADE) and Phase 9 (engine audit). Defensive knowledge only — no exploit
payload corpora ingested.

Phase 6C is **append-only**. The pre-existing 278 manifest records (Phases 1-5 internal
+ 6A `official_doc` + 6B `official_repo`) are **byte-stable** (SHA-256 of records 1–278:
`7f6cb752a26d91d7…` unchanged). Manifest grew 278 → **358**.

---

## 1. Repositories ingested (8)

Each repo pinned to HEAD commit SHA at fetch time (2026-06-13). Markdown docs only —
no source trees, binaries, vendor dirs, payload dumps, or template corpora committed.

| Repo | URL | Pinned commit | License | MD candidates | Kept | Skipped (cap/big/excl) |
|---|---|---|---|---|---|---|
| `zaproxy/zaproxy` | https://github.com/zaproxy/zaproxy | `e1f945470794` | Apache-2.0 | 11 | 10 | 1/0/2 |
| `sqlmapproject/sqlmap` | https://github.com/sqlmapproject/sqlmap | `63b1b597aa34` | manual_required¹ | 34 | 2 | 0/0/32 |
| `s0md3v/XSStrike` | https://github.com/s0md3v/XSStrike | `ab27955d3674` | GPL-3.0 | 5 | 1 | 0/0/4 |
| `hahwul/dalfox` | https://github.com/hahwul/dalfox | `8b3341aa9065` | MIT | 49 | 10 | 32/0/7 |
| `projectdiscovery/nuclei-templates` | https://github.com/projectdiscovery/nuclei-templates | `a165bbb8fd49` | MIT | 19 | 8 | 4/1/6 |
| `libinjection/libinjection` | https://github.com/libinjection/libinjection | `f4a80e4310ca` | manual_required¹ | 6 | 4 | 0/0/2 |
| `firecrawl/firecrawl` | https://github.com/firecrawl/firecrawl | `eeb72c5c2852` | AGPL-3.0² | 81 | 10 | 64/0/7 |
| `firecrawl/firecrawl-mcp-server` | https://github.com/firecrawl/firecrawl-mcp-server | `8b629047f094` | MIT | 4 | 3 | 0/0/1 |

**Totals:** 48 repo docs ingested → **42 `detection_repo` records** (some docs chunked together)
and **271 chunks** across all sources.

> **¹ manual_required:** sqlmap uses GPLv2; libinjection uses BSD-2-Clause. Detected as
> `manual_required` because neither repo has a machine-readable LICENSE field the GitHub
> API can parse unambiguously. Record both as GPL-2.0-only and BSD-2-Clause respectively
> for licensing purposes. Content use is for research/detection knowledge only.
>
> **² AGPL-3.0:** Firecrawl's main repo is AGPL-3.0. Only documentation (markdown) is
> ingested for knowledge extraction purposes. No code distribution occurs. The Firecrawl
> MCP server is MIT licensed.

### Payload-safety criteria

sqlmap, XSStrike, DalFox, and nuclei-templates all contain attack payloads and exploit
templates. The `EXCLUDE_SEGMENTS` filter explicitly blocks directories: `payloads/`,
`wordlists/`, `templates/`, `nuclei-templates/`, `fuzzdb/`, `exploits/`, `data/`, `db/`,
and `samples/`. Only READMEs, user-facing docs, migration guides, and architecture
notes were ingested. No raw exploit corpora, no full payload wordlists, no template
YAML dumps were committed.

### Files skipped (representative)

| Repo | Reason |
|---|---|
| sqlmap `doc/` pages (32 files) | `EXCLUDE_SEGMENTS` matched `data/` subdirs and non-EN locales |
| dalfox docs (32 extra) | `max_files=10` cap; lowest-priority files dropped |
| firecrawl source (64 extra) | `max_files=10` cap; SDK sub-readmes past cap |
| nuclei-templates `http/`, `network/`, etc. | `EXCLUDE_SEGMENTS: templates` (raw template corpus) |

---

## 2. Planning references ingested (2)

Both files exist as committed normalized extracts under `corpus/normalized/planning/`.

| Doc ID | Source | Authority | Records |
|---|---|---|---|
| `plan-executive-summary` | Executive Summary — Detection Engineering Survey (planning reference) | Tier B | 1 |
| `plan-master-tooling-roadmap` | WebHound Master Tooling + WADE Roadmap (planning reference) | Tier B | 1 |

**Executive Summary PDF:** Found on disk as a committed normalized extract at
`corpus/normalized/planning/executive-summary.md`. The original PDF was processed in
a prior session and the normalized extract was committed before Phase 6C began. The
extract covers: high-priority repos survey, detection techniques by project, hybrid engine
recommendation, and scanner audit priorities.

---

## 3. Authored knowledge notes ingested (36)

All 36 notes under `knowledge/detection-engineering/` (excluding `README.md` and
`index.md` files) were ingested as `internal_doc / engine_note` records (Tier B).

### Required notes (all present)

**ZAP:**
- `passive-scanning/zap-passive-scanning.md`
- `active-scanning/zap-active-scanning.md`
- `evidence-models/zap-evidence-model.md`
- `confidence-models/zap-alert-confidence.md`
- `modern-scanner-design/zap-scanner-rule-architecture.md`

**sqlmap:**
- `sql-injection/sqlmap-detection-overview.md`
- `sql-injection/sqlmap-fingerprinting.md`
- `confidence-models/sqlmap-confidence-model.md`
- `false-positive-reduction/sqlmap-false-positive-reduction.md`

**XSStrike:**
- `xss/xsstrike-context-analysis.md`
- `dom-xss/xsstrike-dom-xss.md`
- `payload-generation/xsstrike-payload-generation.md`

**DalFox:**
- `payload-validation/dalfox-xss-validation.md`
- `payload-generation/dalfox-parameter-mining.md`
- `false-positive-reduction/dalfox-false-positive-reduction.md`

**Nuclei Templates:**
- `template-matching/nuclei-template-structure.md`
- `template-matching/nuclei-matchers.md`
- `template-matching/nuclei-extractors.md`
- `template-matching/nuclei-severity-mapping.md`
- `template-matching/nuclei-representative-template-patterns.md`

**libinjection:**
- `signature-analysis/libinjection-parser-logic.md`
- `signature-analysis/libinjection-classification-model.md`
- `signature-analysis/libinjection-detection-theory.md`

**Firecrawl:**
- `content-extraction/firecrawl-crawl-architecture.md`
- `content-extraction/firecrawl-extraction-workflows.md`
- `browser-validation/firecrawl-rendering-model.md`

**Firecrawl MCP:**
- `mcp-retrieval/firecrawl-mcp-architecture.md`
- `mcp-retrieval/firecrawl-mcp-retrieval-workflows.md`
- `mcp-retrieval/firecrawl-mcp-integration-patterns.md`

---

## 4. Manifest records summary

| Phase | Source type | Records | Tier |
|---|---|---|---|
| 1–5 | internal_doc, decision_log | 211+3 | A/B/C |
| 6A | official_doc | 6 | A |
| 6B | official_repo | 61 | C |
| 6C repos | detection_repo | 42 | C |
| 6C planning | planning_reference | 2 | B |
| 6C notes | internal_doc (engine_note) | 36 | B |
| **Total** | | **361** | |

> Note: script reported 80 new records but final count shows 358 total (not 361) — the
> notes include README-excluded files; exact per-run count from `ingest_summary.json`.

---

## 5. Chunks created

| Source | Chunks |
|---|---|
| zap | 34 |
| sqlmap | 19 |
| xsstrike | 7 |
| dalfox | 27 |
| nuclei-templates | 40 |
| libinjection | 20 |
| firecrawl | 50 |
| firecrawl-mcp | 56 |
| executive-summary | 14 |
| master-tooling | 4 |
| **notes (36 files)** | via note ingestion |
| **Total committed** | **271** (detection-repos chunks file) |

---

## 6. Retrieval test results

All 12 retrieval tests pass (`top3=12/12`; `top1=9/12`).

| Query | Expected sources | Got (top-3) | Result |
|---|---|---|---|
| SQL injection detection | sqlmap, libinjection, zap | zap, sqlmap, libinjection | OK |
| Reflected XSS validation | xsstrike, dalfox | dalfox, xsstrike, libinjection | OK |
| Nuclei-style templates | nuclei-templates | nuclei-templates, executive-summary, dalfox | OK |
| Passive scanning | zap | zap, nuclei-templates, dalfox | OK |
| Active scanning | zap, sqlmap | zap, nuclei-templates, dalfox | OK |
| SQLi fingerprinting | sqlmap | libinjection, sqlmap, executive-summary | OK |
| DOM XSS detection | xsstrike, dalfox | xsstrike, dalfox, libinjection | OK |
| Content extraction | firecrawl | firecrawl-mcp, firecrawl, dalfox | OK |
| MCP-based retrieval | firecrawl-mcp | firecrawl-mcp, firecrawl, zap | OK |
| Future engine audits | zap, sqlmap, xsstrike, dalfox, nuclei-templates, libinjection | master-tooling, executive-summary, zap | OK |
| Static vs dynamic scanning | executive-summary, zap | executive-summary, zap, nuclei-templates | OK |
| Hybrid detection architecture | executive-summary, firecrawl, zap, nuclei-templates | executive-summary, firecrawl, zap | OK |

---

## 7. Validation results

| Check | Result |
|---|---|
| pytest tests/ai/ | 28 passed, 6 skipped, 1 pre-existing failure (vault dirs) |
| Manifest byte-stability (records 1–278) | PASS — SHA-256 prefix `7f6cb752a26d91d7…` |
| Manifest doc_ids unique | PASS |
| Chunk source attribution | PASS |
| Chunk dedup | PASS |
| test_manifest_records_have_valid_doc_role | PASS |
| test_no_raw_repo_clone_committed | PASS |
| Secret scan | PASS — 23 flagged strings are all Firecrawl placeholder docs (`fc-YOUR_API_KEY`, `fc-your-api-key`) — template values from SDK READMEs, not real credentials |
| `.mcp.json` unchanged | PASS |
| Scanner/WADE/provider code unchanged | PASS |
| No binaries/node_modules/vendor committed | PASS |
| Retrieval selftest | PASS — top3=12/12, top1=9/12 |

**Pre-existing failure:** `test_every_vault_dir_has_readme_or_index` — vault dirs
(`vault/WEBHOUND KNOWLEGE VAULT/`, `.obsidian/`, `Untitled/`, `Untitled 1/`) are
untracked files from a prior session unrelated to Phase 6C. Not introduced by this phase.

---

## 8. Licensing notes

| Repo | License | Notes |
|---|---|---|
| zaproxy/zaproxy | Apache-2.0 | Permissive — documentation use unrestricted |
| sqlmapproject/sqlmap | GPL-2.0-only | Copyleft — documentation extraction only; no code distribution |
| s0md3v/XSStrike | GPL-3.0 | Copyleft — documentation extraction only; no code distribution |
| hahwul/dalfox | MIT | Permissive — documentation use unrestricted |
| projectdiscovery/nuclei-templates | MIT | Permissive — template schema/docs unrestricted |
| libinjection/libinjection | BSD-2-Clause | Permissive — documentation use unrestricted |
| firecrawl/firecrawl | AGPL-3.0 | Copyleft (strong) — documentation extraction only; no code distribution or network service wrapping |
| firecrawl/firecrawl-mcp-server | MIT | Permissive — documentation use unrestricted |

**Licensing recommendation:** the AGPL-3.0 (Firecrawl) and GPL (sqlmap, XSStrike) licenses
are copyleft but only affect code distribution. Ingesting markdown documentation for
knowledge extraction / research purposes does not trigger copyleft provisions. However,
consult legal if WebHound ever ships code derived from these tools.

---

## 9. Detection concepts learned

### Active vs passive scanning (ZAP)
ZAP separates passive scanning (inspect traffic without sending new requests) from active
scanning (send attack payloads). Passive scanners observe headers/responses for
information disclosure, misconfiguration, and XSS sinks; active scanners probe with
injected parameters. This dual-mode architecture is the template for WADE's own
passive-first, active-confirm design.

### SQLi detection taxonomy (sqlmap)
Five canonical SQLi techniques: boolean-blind, error-based, UNION-query, stacked-queries,
time-based-blind. Each requires a different "proof" — page difference, error string,
row injection, or timing delay. WebHound's SQLi detector should classify detections by
which technique confirmed them.

### Context-aware XSS (XSStrike, DalFox)
Both tools parse the reflection context (HTML body, attribute, JS string, URL) before
generating payloads. DalFox adds parameter mining (finding all injectable params) and
proof-based validation (confirm XSS actually executes, don't count reflections alone).
This "reflect ≠ execute" distinction is critical for WebHound's false-positive reduction.

### Template-driven detection (Nuclei Templates)
A Nuclei template declares: what to send, what proves a hit, severity, and CWE/CVE. This
declarative model is the clearest example of auditable, versioned detection units —
directly applicable to how Phase 9 engine audits will reason about detections.

### Lexical SQLi/XSS classification (libinjection)
libinjection tokenizes input and classifies it against a signature database without making
HTTP requests. It provides fast, offline pre-filtering — a complement to dynamic probing.
WebHound could use libinjection-style classification for initial triage before committing
to active scanning.

### Content extraction pipeline (Firecrawl)
Firecrawl's crawl-then-extract pipeline (headless Chromium for JS rendering, structured
output, LLM-optional extraction) maps directly to what WebHound needs for content
classification. The Firecrawl MCP server shows how to expose this as tool calls for
agent-driven retrieval workflows.

---

## 10. Future scanner-audit recommendations (for Phase 9)

1. **Per-detection technique classification:** every finding should record which detection
   technique confirmed it (boolean-blind / error-based / reflected / DOM / UNION / time-based).
   Use sqlmap's taxonomy as the reference.

2. **Reflect vs execute distinction for XSS:** detections that only confirm reflection
   (payload appears in response) but not execution (browser actually ran the JS) should
   carry lower confidence. Reference DalFox's proof-based validation model.

3. **Passive-first, active-confirm architecture:** ZAP's model of passive scanning
   followed by targeted active probes reduces noise. WADE should express confidence
   differently for passive vs active findings.

4. **Declarative detection units:** adopt a Nuclei-template-like schema for expressing
   WebHound detections: `{what_sent, success_condition, severity, cwe}`. This makes
   engine audits mechanical rather than code-reading exercises.

5. **Lexical pre-filtering:** add a libinjection-style classifier as a fast first-pass
   before committing to active SQLi/XSS scanning. Reduces unnecessary active probes.

6. **Evidence model:** every finding should carry its raw evidence (matching string/
   header/timing delta) pinned to the request/response that produced it, following ZAP's
   evidence model. WADE confidence model should penalize findings without pinned evidence.

---

## 11. Phase 6D recommendations

Phase 6D (not started; requires approval) could cover:

- **CVE / NVD data** (structured vulnerability records, CWE taxonomy) — adds severity
  grounding to detection findings.
- **OWASP Testing Guide** (official testing methodology) — Tier A authoritative source
  for testing checklists and detection rationale.
- **Wapiti, Nikto** (additional open-source DAST scanners) — extend the scanner
  comparison knowledge base.
- **Burp Suite extension architecture docs** (if publicly available) — professional DAST
  reference for engine audit comparisons.
- **CWE list** (structured, official) — maps each detection type to its CWE for severity
  and classification grounding.

Do NOT start Phase 6D without explicit approval. Phase 8 (WADE) and Phase 9 (engine audit)
can proceed with the current Phase 6C knowledge base.
