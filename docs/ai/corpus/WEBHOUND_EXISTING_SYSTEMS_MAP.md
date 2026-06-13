# WebHound Existing-Systems Map (reuse, do NOT rebuild)

The corpus/knowledge layer sits **on top of** WebHound's existing runtime systems.
This map records each system's real code path (verified in the Phase-0 gap report),
its future relationship to the knowledge layer, and the reuse strategy. **The
knowledge layer references these; it never re-implements them.**

---

## 1. Threat Intelligence (runtime)
- **Purpose:** detect known-bad hosts/URLs/script-hashes during scans; enrich
  findings. Offline-by-design (feeds loaded from `WEBHOUND_THREAT_FEED_DIR`).
- **Owner (code):** `scanner/webhound/threat_intel/` (`feed_manager`,
  `feed_normalizer`, `enrichment_service`, `domain_reputation`, `script_reputation`,
  `reputation_cache`, `supply_chain`, `brand_impersonation`, `threat_correlation`,
  `coverage`); API: `apps/api/services/threat_intel.py`,
  `apps/api/models/threat_indicator.py` (+ migration `0024_threat_intel`); wired in
  `scanner/webhound/core/orchestrator.py` + `engines/threat_intel/external_domains.py`.
- **Future relationship:** corpus stores *evidence about feeds* (`raw/feeds/`,
  `normalized/feeds/`) + provenance; knowledge graph links `finding_type →
  threat_feed`. **Indicators remain in the runtime store.**
- **Reuse strategy:** call/reference `feed_manager` + `threat_indicator`; reuse
  `feed_normalizer`. Phase 5 adds only **net-new** feeds, never a parallel store.

## 2. URLHaus client
- **Purpose:** abuse.ch malware-URL reputation lookups.
- **Owner (code):** `scanner/webhound/threat_intel/urlhaus_client.py` (live client,
  offline-safe) + `normalize_urlhaus`; flags `ENABLE_URLHAUS`, `URLHAUS_API_KEY`.
- **Future relationship:** Tier-D evidence source; corpus records the feed's
  provenance/coverage, not its indicators.
- **Reuse strategy:** **existing** — reuse as-is; do not rebuild.

## 3. VirusTotal client
- **Purpose:** domain reputation via VirusTotal v3.
- **Owner (code):** `scanner/webhound/threat_intel/virustotal_client.py` +
  `normalize_virustotal`; `VIRUSTOTAL_API_KEY`.
- **Future relationship:** Tier-D enrichment; corpus records provenance.
- **Reuse strategy:** **existing** — reuse as-is.

## 4. WADE (drift / anomaly engine)
- **Purpose:** baseline a site and detect meaningful change/compromise over time.
- **Owner (code):** `scanner/webhound/wade/` (`classifier`, `context_engine`,
  `anomaly_scorer`, `baseline_*`, `change_*`, `suppression`, `vendor_intel`,
  `quality_review`, `confidence`, `diff_engine`, `timeline`); API:
  `apps/api/services/wade_correlation.py`.
- **Future relationship:** Phase-8 **knowledge-enrichment interface** will *suggest*
  context to WADE/findings (suggest-only, no auto-suppress). Graph links
  `WADE_rule → evidence_source`.
- **Reuse strategy:** integrate via a thin interface against the existing modules +
  `FindingRecord`; never a parallel WADE.

## 5. Security Graph (per-scan runtime graph)
- **Purpose:** build a deterministic `SecurityGraph` of one scan's findings/entities
  (incl. `THIRD_PARTY_DOMAIN` nodes).
- **Owner (code):** `scanner/webhound/graph/` (`graph_builder`, `graph_query`,
  `graph_scoring`, `relationship_extractor`, `graph_export`, `graph_validator`,
  `models`).
- **Future relationship:** **distinct** from the corpus knowledge graph
  (`corpus/graph/`, Phase 4). At most a read-only bridge.
- **Reuse strategy:** reference for entity/relationship modeling; do not merge
  stores. (Known FP #4 — third-party-domain node ingestion — lives here.)

## 6. Validation Framework (detection-quality lab)
- **Purpose:** measure scanner precision/recall/coverage against ground-truth mock
  sites; gate regressions.
- **Owner (code):** `scanner/validation/` (`ground_truth`, `benchmark_runner`,
  `finding_validator`, `precision_report`, `recall_report`, `framework_scorecard`,
  `coverage_report`, `regression_runner`); exercised by
  `scanner/tests/test_validation_lab.py`.
- **Future relationship:** Phases 7/9/10 reuse + extend this (goldens, audits,
  benchmarks). Graph links `scanner_engine → finding_type`.
- **Reuse strategy:** extend ground-truth targets + harness; **do not author a new
  framework**. (No CI runs it today — known gap.)

## 7. Benchmark Harness
- **Purpose:** compare a `ScanResult` to `expected_findings` /
  `expected_non_findings` / `expected_risk_range`.
- **Owner (code):** `scanner/webhound/benchmark/harness.py`.
- **Future relationship:** Phase-10 benchmark plan builds on it.
- **Reuse strategy:** reuse the harness; feed it Phase-7 synthetic goldens.

## 8. Provider Access Framework
- **Purpose:** detect CDN/WAF providers, drive scanner-allowlisting (CF API
  automation; Vercel manual), and provider remediation.
- **Owner (code):** `apps/api/services/` — `provider_access_registry.py` (10
  providers), `platform_access.py`, `cloudflare*.py`, `vercel*.py`,
  `provider_discovery.py`, `trusted_access.py`, `scanner_access_diagnosis.py`;
  models `provider_connection`, `provider_profile`.
- **Future relationship:** the **authoritative ground truth** for provider behavior;
  `provider-docs/` knowledge (Phase 3) cites Tier-A provider docs that match the
  registry. Graph links `provider → allowlist_method`.
- **Reuse strategy:** treat the registry as source of truth; never re-derive
  provider behavior. (Vercel "Seawall"/`pending_firewall_setup` behavior is already
  encoded here.)

## 9. Support / Ticket System
- **Purpose:** customer tickets + internal notes; platform-access escalation.
- **Owner (code):** `apps/api/services/support.py`, `support_ticket.py`,
  `tickets.py`; models `support_ticket`, `internal_note`;
  `/platform-access/support-ticket` endpoint.
- **Future relationship:** support playbooks (Phase 6) reference this; escalation
  evidence may be summarized (sanitized, no customer PII) into knowledge.
- **Reuse strategy:** reference the existing ticket flow; never duplicate it; never
  ingest customer PII.

## 10. Anthropic Summarizer (existing Claude path)
- **Purpose:** AI scan-result summaries (feature-flagged, default off).
- **Owner (code):** `apps/api/services/ai_summary.py`; `WEBHOUND_AI_ENABLED` +
  `ANTHROPIC_API_KEY` in `apps/api/config.py` (fails fast if enabled without key).
- **Future relationship:** the knowledge layer's Claude usage **reuses this flag +
  key**; "Claude memory summaries" align with it.
- **Reuse strategy:** **no parallel AI config** — gate on the existing flag/key.

---

### Out-of-scope artifact
`ruvector.db` (repo root) is an **orphaned redb file** from claude-flow tooling —
not WebHound runtime state, referenced nowhere in app code. **Ignore it**; the
Phase-4 knowledge store runs beside it.
