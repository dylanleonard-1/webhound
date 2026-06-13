# WADE Foundation — Summary (pointer-first)

Curated summary of WADE as it exists **today**. Ground truth = `scanner/webhound/
wade/` + `apps/api/services/wade_correlation.py` + `docs/wade.md`.

## What WADE is
WADE is WebHound's **baseline + change-intelligence** foundation: it baselines a
site, then on later scans detects meaningful change/drift and possible compromise
(rather than re-reporting the same static posture each time).

## Components (code)
`scanner/webhound/wade/`: `baseline_builder`, `baseline_store`, `diff_engine`,
`change_classifier`, `change_types`, `anomaly_scorer`, `confidence`,
`context_engine`, `suppression`, `vendor_intel`, `timeline`, `quality_review`,
`classifier`. API correlation: `apps/api/services/wade_correlation.py`. UI:
`apps/web/src/components/{monitoring/wade-history-timeline,results/wade-summary}.tsx`.

## Current state
WADE is a working drift/anomaly engine. It is **not yet knowledge-enriched** — it
does not consume the AI Knowledge Layer.

## Future relationship (NOT this phase)
A later phase (Phase 8) will add a **knowledge-enrichment interface** that can
*suggest* context to WADE/findings (risk context, references, candidate
downgrades/suppressions). Rules for that phase:
- **Suggest-only.** Enrichment suggests; the scanner/WADE decides.
- **No auto-suppress, no auto-severity-change, no scoring change.**
- Integrate with existing WADE modules + the `FindingRecord` shape — never a
  parallel WADE.

## Phase 3 scope
**Documentation only.** No WADE code, scoring, or behavior is changed in Phase 3.

**Review status:** curated (seeded Phase 3). **Authority:** trusted_local.
