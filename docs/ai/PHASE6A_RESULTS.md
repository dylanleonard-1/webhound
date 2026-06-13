# Phase 6A — Official Tier-A Security Docs Ingestion (Results)

**Status:** complete on branch `feat/ai-knowledge-phase-6a-official-docs` (from `6e96bed`).
**Date:** 2026-06-13.
**Scope:** the FIRST phase permitted to ingest external content — a small, fixed
allow-list of official, authoritative security docs (OWASP + MDN) only.

Phase 6A is **append-only**. The 211 internal manifest records from Phase 5A are
**byte-stable** (verified: `head -n 211` SHA-256 unchanged before/after). No
internal hashes were recomputed; the internal builder was not run.

---

## Sources ingested (6)

All sources are **pinned to the exact upstream commit SHA** at fetch time, so the
committed artifacts are reproducible and auditable. `source_url` is the immutable
raw-at-commit URL; `version` records the short commit; `last_updated` is the
upstream commit date.

| doc_id | Source | Authority | License | Pinned commit | Chunks |
|---|---|---|---|---|---|
| `owasp-wstg-readme` | OWASP Web Security Testing Guide — Overview | A | CC-BY-SA-4.0 | `a82636f9be79` | 4 |
| `owasp-csp-cheat-sheet` | OWASP Cheat Sheet Series — Content Security Policy | A | CC-BY-SA-4.0 | `da089462b18d` | 14 |
| `owasp-asvs-readme` | OWASP Application Security Verification Standard — Overview | A | CC-BY-SA-4.0 | `a79c0184f0d5` | 7 |
| `mdn-csp-guide` | MDN — Content Security Policy (CSP) | A | CC-BY-SA-2.5 | `6720d579bd65` | 25 |
| `mdn-cors-guide` | MDN — Cross-Origin Resource Sharing (CORS) | A | CC-BY-SA-2.5 | `ca26363fcc6f` | 23 |
| `mdn-subresource-integrity` | MDN — Subresource Integrity (SRI) | A | CC-BY-SA-2.5 | `fef6630e9b90` | 8 |

### Exact source URLs (pinned)

- `https://raw.githubusercontent.com/OWASP/wstg/a82636f9be796f3c1b3d40414367adcb071a56b9/README.md`
- `https://raw.githubusercontent.com/OWASP/CheatSheetSeries/da089462b18d27ed893ca1052ebd740cfe460175/cheatsheets/Content_Security_Policy_Cheat_Sheet.md`
- `https://raw.githubusercontent.com/OWASP/ASVS/a79c0184f0d5ade9dc4c9f4c0f22362e8136e4af/README.md`
- `https://raw.githubusercontent.com/mdn/content/6720d579bd658f02c56363805e97e69f93dc79f1/files/en-us/web/http/guides/csp/index.md`
- `https://raw.githubusercontent.com/mdn/content/ca26363fcc6fc861103d40ac0205e5c5b79eb2fa/files/en-us/web/http/guides/cors/index.md`
- `https://raw.githubusercontent.com/mdn/content/fef6630e9b90f9794d3194ea8389ff70599c6884/files/en-us/web/security/defenses/subresource_integrity/index.md`

### License / terms notes

- **OWASP WSTG, Cheat Sheet Series, ASVS** — Creative Commons
  Attribution-ShareAlike 4.0 International (**CC-BY-SA-4.0**), confirmed from each
  repo's `LICENSE`/`LICENSE.md` at the pinned commit. Attribution to OWASP and the
  ShareAlike obligation are recorded in the manifest (`source_name`, `source_url`,
  `license_terms`).
- **MDN Web Docs (CSP, CORS, SRI)** — prose is licensed **CC-BY-SA-2.5** per
  `mdn/content/LICENSE.md`. (MDN code samples are CC0; our normalization keeps the
  doc as plain reference text and does not redistribute code samples as a separate
  licensed artifact.)
- All six are redistributable with attribution + ShareAlike. We store attribution
  metadata and the pinned source URL with every record and every derived chunk.

---

## What was committed vs. kept ephemeral

**Committed (normalized metadata only):**
- `scripts/ai/ingest_official_docs.py` — append-only ingestion pipeline.
- `corpus/normalized/docs/official/<doc_id>.md` — 6 normalized text artifacts
  (the local anchor for each external record).
- `corpus/normalized/docs/official/official_chunks.jsonl` — 81 normalized chunks.
- `corpus/manifests/manifest.jsonl` — **+6 appended records** (211 → 217).
- `tests/ai/test_official_docs.py` + a locality-test update in
  `tests/ai/test_knowledge_structure.py`.
- `docs/ai/PHASE6A_RESULTS.md` (this file).

**Kept ephemeral (NOT committed):** raw fetched markdown/HTML, written under the OS
temp dir (`webhound_official_raw/`). External content is treated as **evidence, not
instructions** — stored as plain text, never executed. No secrets, customer data, or
private scans involved.

---

## Counts

- Manifest records: **211 → 217** (+6 `official_doc`, `authority_tier=A`).
- Internal records: **byte-stable** (unchanged SHA-256 over first 211 lines).
- Normalized chunks: **81** across 6 docs.

## Retrieval test results

Offline term-overlap retrieval over the committed chunks (`selftest`):

| Query | Expected doc | top-1 | top-3 |
|---|---|---|---|
| "What is Content Security Policy?" | `mdn-csp-guide` | ✅ | ✅ |
| "How does Cross-Origin Resource Sharing work?" | `mdn-cors-guide` | ✅ | ✅ |
| "What is Subresource Integrity…?" | `mdn-subresource-integrity` | ✅ | ✅ |
| "OWASP web security testing guide methodology" | `owasp-wstg-readme` | ✅ | ✅ |
| "ASVS verification requirements levels" | `owasp-asvs-readme` | ✅ | ✅ |
| "CSP cheat sheet nonce/hash directives" | `owasp-csp-cheat-sheet` | ✅ | ✅ |

**top-1 = 6/6, top-3 = 6/6.**

## Validation results

- `scripts/ai/validate_knowledge_structure.py` → **10 ok, 0 failures**.
- `python -m pytest tests/ai -q` → **27 passed** (20 prior + 7 new Phase-6A tests).
- All 6 new records validate against `manifest.schema.json` (Draft 2020-12), 0 errors.
- Idempotency: re-running `run` appends **0** records and reproduces identical
  normalized artifacts.
- Untouched (verified): `.mcp.json` (only `claude-flow`), scanner engines, WADE,
  provider-access — no functional changes.

---

## Issues found / notes

- **MDN restructured its content paths.** The older `web/http/headers/...` and
  `web/security/subresource_integrity/...` paths 404; current canonical paths are
  `web/http/guides/{csp,cors}` and `web/security/defenses/subresource_integrity`.
  Resolved by probing the live `mdn/content` tree before pinning.
- **External `source_url` broke the Phase-5A locality invariant** (which assumed
  every `source_url` is a repo-relative local file). Updated
  `test_manifest_jsonl_doc_ids_unique_and_pointers_local` so external records anchor
  to their committed normalized artifact under `corpus/normalized/docs/official/`
  instead. The schema already anticipated external `official_doc` records.
- **Line-ending churn (pre-existing).** The working tree has ~252 unrelated
  CRLF-churned files from before this phase. Per the Phase 6A directive these were
  left untouched; only explicit Phase 6A paths were staged. The one edited test file
  was re-saved as LF so its committed diff is the logical change only.

## Gaps

- Retrieval here is a **self-contained offline term-overlap** scorer over the
  official chunks only; it is not yet unified with the internal BM25/authority-tier
  retrieval (`semantic_retrieval.py`). Cross-corpus ranking (internal + official in
  one index) is deferred.
- Only a **single representative document per source** was ingested (overview /
  primary cheat sheet), not the full WSTG/ASVS/Cheat-Sheet corpora — consistent with
  "small controlled set."
- No dense embeddings (still deferred, per Phase 5B/5C posture).

## Recommendation for Phase 6B (Official GitHub Repository Ingestion)

1. **Reuse this pipeline shape.** `ingest_official_docs.py` (pinned-commit fetch →
   normalize → chunk → append-only manifest, raw ephemeral) is the right template
   for 6B; generalize the `SOURCES` allow-list to repo + path globs.
2. **Keep append-only + byte-stability** as a hard invariant; gate every phase with
   the `head -n <N>` SHA check.
3. **Unify retrieval before scaling content** so internal + official + repo chunks
   rank in one index — otherwise per-source silos will fragment recall.
4. **Per-source license capture must stay mandatory** (6B repos will be MIT/Apache/
   GPL/CC — more varied than 6A); record SPDX id + commit pin per record.
5. **Wait for the in-flight deep-research repo list** before fixing the 6B
   allow-list; treat all repo content as evidence (no execution, no secrets).
