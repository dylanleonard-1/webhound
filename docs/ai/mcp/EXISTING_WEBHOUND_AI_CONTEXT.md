# Existing WebHound AI / Knowledge Substrate (reuse — do NOT duplicate)

This is the ground truth the AI Knowledge Layer must build **on top of**, verified
by direct repo inspection in Phase 0. Every claim below was confirmed in code.

## Existing Claude / AI path — reuse this, no parallel config
- **`WEBHOUND_AI_ENABLED`** (`apps/api/config.py`, default `False`) +
  **`ANTHROPIC_API_KEY`**.
- Current use: the **scan-result summariser** in `apps/api/services/ai_summary.py`.
  When `WEBHOUND_AI_ENABLED=1` **and** a key is set, it switches from a
  deterministic/template summary to a **live Claude** summary; config **fails
  fast** if enabled without the key.
- This is the **only** Claude integration in the codebase.
- **Implication:** the knowledge layer reuses this flag + key (and its fail-fast
  gating). Do **not** introduce a second AI on-switch or a parallel key.

## Existing threat intelligence (runtime) — extend, don't rebuild
`scanner/webhound/threat_intel/` is substantial and **wired into scans**
(`core/orchestrator.py`, `engines/threat_intel/external_domains.py`,
`domain_reputation.py`, `script_reputation.py`). Offline-by-design: feeds load
from a local dir (`WEBHOUND_THREAT_FEED_DIR`); live lookups are operator-gated.

| Feed | State (verified) |
|------|------------------|
| **URLHaus** | **Live client** (`urlhaus_client.py`) + normalizer. `ENABLE_URLHAUS`, optional `URLHAUS_API_KEY`. |
| **VirusTotal** | **Live client** (`virustotal_client.py`) + normalizer. `VIRUSTOTAL_API_KEY`. |
| **OpenPhish** | **PARTIAL** — `normalize_openphish` exists, **no fetch client**. |
| **AbuseIPDB** | **PARTIAL** — `normalize_abuseipdb` exists, **no fetch client** (no key yet). |
| **PhishTank** | normalizer exists (`normalize_phishtank`). |
| **ThreatFox** | **MISSING** — no client, no normalizer. |
| **AlienVault OTX** | **MISSING** — no client, no normalizer. |

Phase 5 scope is therefore **net-new**: build ThreatFox + OTX (full), add fetch
clients for OpenPhish + AbuseIPDB (normalizers already exist). Reuse
`feed_normalizer`, `feed_manager`, `WEBHOUND_THREAT_FEED_DIR`, and the
`threat_indicator` model — never duplicate the existing clients.

## Security Graph ≠ knowledge graph
`scanner/webhound/graph/` ("Phase-20 Security Graph Engine") builds a
**per-scan, runtime `SecurityGraph`** from findings/crawl/browser/WADE/threat
correlations (deterministic; `NodeType` includes `THIRD_PARTY_DOMAIN`). It is
**evidence about one scan**, NOT the long-term RAG/knowledge graph that Phase 4
will build. Keep them separate; a read-only bridge is the most they should share.

## WADE — integrate, don't fork
`scanner/webhound/wade/` (classifier, context_engine, anomaly_scorer, baseline,
suppression, vendor_intel, quality_review) + `apps/api/services/wade_correlation.py`.
The Phase-8 enrichment **interface** is new, but it must integrate with these and
the `FindingRecord` shape — never a parallel WADE.

## Validation / benchmark harness — reuse later (Phases 7/9/10)
`scanner/validation/` (ground-truth lab, precision/recall, coverage 0–100 quality
score, regression gate) + `scanner/webhound/benchmark/harness.py`
(expected-findings / expected-non-findings / risk-range). Exercised by
`test_validation_lab.py`. Reuse and extend; do not author a new framework.

## `ruvector.db` — ignore
Root-level `ruvector.db` is a **redb** file (not SQLite) created by the
`claude-flow`/ruv tooling. **Zero references** in WebHound code; stale; not app
state. The knowledge layer runs **beside** it — never wraps/replaces it.

## No CI — known gap
There is **no `.github/workflows`** and no repo-self SAST/secret-scan. The
validation/regression gate exists but nothing runs it automatically. A minimal CI
is a candidate for a later phase (not assumed, not added in Phase 1).

## Env source of truth
`.env.example` is **generated** by `scripts/_gen_env_example.py` (writes the root
`.env.example` for api/worker/scanner and `apps/web/.env.example` for the
frontend). Reference doc: `docs/env.md`. **Never hand-edit `.env.example`.**
