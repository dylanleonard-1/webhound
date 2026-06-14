---
title: WADE
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 08 — WADE

WADE (WebHound Analysis & Decision Engine) is the post-processing layer that reduces noise, applies confidence scoring, and detects cross-scan behavioural patterns.

## Components

| Layer | Status | Source |
|-------|--------|--------|
| Confidence scoring | ✅ Live | Per-finding `confidence` field |
| FP rules | ✅ Live | `models/suppression.py` + user rules |
| Cross-scan correlation | ✅ Live | `services/wade_correlation.py` |
| Knowledge retrieval | ✅ Live | Brain v8B · 22 finding types |
| Graph-enhanced retrieval | ⏳ Pending | Phase 9A |

## Existing Phase 8A Notes

- [[08-WADE/WADE Overview|WADE Overview]] — core concepts
- [[08-WADE/WADE Confidence Model|Confidence Model]] — scoring algorithm
- [[08-WADE/WADE FP Rules|FP Rules]] — false-positive rule catalog
- [[08-WADE/WADE Retrieval Interface|Retrieval Interface]] — knowledge retrieval

→ [[08-WADE/WADE Layer Map|Full Layer Map]] (Phase 8G)

## Cross-Scan Behavioural Correlation

Five rules in `apps/api/services/wade_correlation.py`:

1. **tech_stack_churn** — ≥3 distinct tech changes across N scans
2. **tls_instability** — ≥2 TLS-config changes in N scans
3. **third_party_explosion** — domain count ≥3× median of prior N-1 scans
4. **persistent_header_regression** — same security header absent across last N scans
5. **admin_surface_flapping** — login form appears/disappears across scans

## Finding Types Covered (Brain v8B)

22 finding types retrievable from knowledge corpus via hybrid retrieval.

## See Also

- [[07-Scanner/index|Scanner]] · [[09-Threat Intelligence/index|Threat Intel]]
- [[13-Knowledge Corpus/index|Knowledge Corpus]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #wade #index

## Merged from Phase 8A (03-WADE)

- [[08-WADE/WADE Confidence Model|WADE Confidence Model]]
- [[08-WADE/WADE FP Rules|WADE FP Rules]]
- [[08-WADE/WADE Overview|WADE Overview]]
- [[08-WADE/WADE Retrieval Interface|WADE Retrieval Interface]]
