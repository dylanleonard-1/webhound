# Phase 6E Results — Threat Intelligence Source Documentation & Confidence Model

Date: 2026-06-13
Branch: feat/ai-knowledge-phase-6e-threat-intel-sources

## Summary

Phase 6E adds threat intelligence source documentation, confidence models, false-positive
models, and WADE-integration guidelines to the WebHound AI knowledge layer.
No scanner, WADE, provider-access, or production changes. No live threat-feed data.
Prior 424 manifest records are byte-stable (SHA256 prefix: `fd5a1449c94a16c9`).

## Manifest Count

| Milestone | Count |
|---|---|
| Pre-Phase-6E (start) | 424 |
| Phase 6E additions | +24 |
| **Post-Phase-6E total** | **448** |

## Sources Fetched vs Skipped

### Live-fetched (official_threat_intel_doc, authority_tier=A) — 9 sources

| Source | URL fetched | Status |
|---|---|---|
| URLHaus | urlhaus-api.abuse.ch/ | OK |
| ThreatFox | threatfox.abuse.ch/api/ | OK (followed 301) |
| OpenPhish | openphish.com/phishing_database.html | OK (partial) |
| PhishTank | phishtank.com/developer_info.php | OK |
| AbuseIPDB | docs.abuseipdb.com/ | OK |
| VirusTotal | docs.virustotal.com/reference/overview | OK |
| Google Safe Browsing | developers.google.com/safe-browsing/v4/lookup-api | OK |
| GreyNoise | docs.greynoise.io/docs/using-the-greynoise-community-api | OK |
| Shodan | developer.shodan.io/api | OK |

### Authored synthesis (internal_doc, authority_tier=B) — 3 sources

| Source | Reason | live_fetch_status |
|---|---|---|
| AlienVault OTX | JS-heavy SPA; /api/v1/docs returned 404; LevelBlue rebranding | blocked |
| Censys | docs.censys.com session-limit; search.censys.io/api returned 403 | blocked |
| MISP | misp-project.org/documentation returned minimal navigation content | partial |

## Normalized Files Created

12 per-source files in `corpus/normalized/threat-intel/`:
- `urlhaus/pd-ti-urlhaus--api.md`
- `threatfox/pd-ti-threatfox--api.md`
- `openphish/pd-ti-openphish--feed.md`
- `phishtank/pd-ti-phishtank--api.md`
- `abuseipdb/pd-ti-abuseipdb--api.md`
- `virustotal/pd-ti-virustotal--api.md`
- `google-safe-browsing/pd-ti-gsb--lookup-api.md`
- `greynoise/pd-ti-greynoise--community-api.md`
- `shodan/pd-ti-shodan--api.md`
- `otx/pd-ti-otx--api.md`
- `censys/pd-ti-censys--api.md`
- `misp/pd-ti-misp--overview.md`

## Knowledge Files Created

`knowledge/threat-intelligence/` — 13 READMEs (1 top-level + 12 per-source),
12 per-source notes, and 12 synthesis/model docs:

- `threat-intel-source-overview.md` — source matrix, client status
- `indicator-type-model.md` — indicator types and source coverage
- `threat-intel-confidence-model.md` — 12-factor confidence model
- `threat-intel-false-positive-model.md` — 12 FP scenarios
- `shared-infrastructure-risk.md` — CDN/cloud/shared hosting risks
- `url-vs-domain-vs-ip-confidence.md` — specificity hierarchy
- `threat-intel-for-wade.md` — MUST NOT / SHOULD rules for WADE
- `threat-intel-for-third-party-scripts.md` — script TI, Magecart detection
- `threat-intel-for-phishing-detection.md` — 3 phishing detection scenarios
- `threat-intel-for-malicious-redirects.md` — redirect chain analysis
- `threat-intel-for-customer-reporting.md` — prohibited language, severity mapping
- `threat-intel-source-terms-and-limits.md` — license/terms/rate-limits table

## Chunks

| File | Chunks |
|---|---|
| `corpus/normalized/threat-intel/threat_intel_chunks.jsonl` | 96 |
| Source breakdown (9 official) | ~4 chunks each |
| Synthesis notes | ~51 chunks combined |

## Retrieval Self-Tests (22 of 22 passed)

All 22 tests in `test_knowledge_structure.py`:
1. URLHaus malware URL confidence — PASS
2. ThreatFox IOC types (cc_skimming, botnet_cc) — PASS
3. OpenPhish phishing URL source — PASS
4. PhishTank community verification — PASS
5. OTX pulse/source model — PASS
6. AbuseIPDB shared-IP false positives — PASS
7. VirusTotal domain/IP/URL lookup semantics — PASS
8. Google Safe Browsing unsafe URL lookup — PASS
9. GreyNoise internet-noise IP context (riot) — PASS
10. Shodan exposure vs maliciousness — PASS
11. Censys exposure vs maliciousness — PASS
12. MISP threat-sharing structure (to_ids) — PASS
13. URL-level vs domain-level confidence — PASS
14. Shared hosting/CDN FP risk — PASS
15. Multiple-source confirmation — PASS
16. Stale IOC handling — PASS
17. Third-party script domain TI (Magecart) — PASS
18. Malicious redirect TI — PASS
19. Phishing landing page TI — PASS
20. WADE threat-intel reasoning — PASS
21. Customer-safe TI reporting — PASS
22. TI source terms/rate limits — PASS

## Full Test Suite

```
59 passed, 0 failed in 4.99s
```

## Invariant Checks

| Check | Result |
|---|---|
| Prior 424 records byte-stable | YES |
| Duplicate doc_ids | 0 |
| Forbidden tokens (API keys, secrets) | 0 |
| .mcp.json unchanged (claude-flow only) | YES |
| scanner/ changes | NONE |
| WADE/provider-access changes | NONE |
| apps/ source changes | NONE |
| Files > 500 lines | NONE |
| Raw IOC lists in repo | NONE |
| Customer/private scan data | NONE |

## Schema Changes

`corpus/manifests/manifest.schema.json`: Added `"official_threat_intel_doc"` to
`source_type` enum (first added mid-phase after schema lookup; retained in 6E).

## Licensing Notes

1. **abuse.ch (URLHaus, ThreatFox)**: Commercial use may require paid subscription.
   WebHound's commercial nature should be reviewed against their ToU.
2. **Google Safe Browsing**: Must display "Google Safe Browsing" attribution in any
   consumer-facing UI presenting these results. Required — not optional.
3. **VirusTotal**: No raw data redistribution; attribution required in customer reports.
4. **PhishTank (Cisco Talos)**: Governed by Cisco EULA; verify commercial terms.
5. **AbuseIPDB**: Raw report comments may contain PII — do not expose in customer outputs.

## Merge/Review Recommendation

All tests pass, invariants verified, no production changes.
PR is ready for review. Do NOT merge until:
- Phase 6D manifest records confirmed on main (Phase 6D was merged as PR #6)
- Reviewer has checked licensing notes above against WebHound commercial terms
