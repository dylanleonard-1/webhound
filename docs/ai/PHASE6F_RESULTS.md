# Phase 6F Results — CVE/CWE/CVSS/NVD Vulnerability Taxonomy Knowledge Layer

Date: 2026-06-14
Branch: feat/ai-knowledge-phase-6f-vulnerability-taxonomy

## Summary

Phase 6F documents 12 official vulnerability taxonomy sources (MITRE CWE definitions,
NVD, CVSS v3.1/v4.0, OWASP) and 17 authored synthesis/policy notes covering CVE/CWE/
CVSS/KEV/OWASP methodology as applied to WebHound scanner findings.
No scanner, WADE, provider-access, or production changes. No bulk CVE/NVD dumps.
Prior 424 and 448 records are byte-stable.

## Manifest Count

| Milestone | Count |
|---|---|
| Pre-Phase-6F (Phase 6E baseline) | 448 |
| Phase 6F additions | +39 |
| **Post-Phase-6F total** | **487** |

Breakdown: 22 `official_taxonomy_doc` (authority_tier=A) + 17 `internal_doc` (authority_tier=B)

## Byte Stability

| Baseline | SHA256 prefix | Match |
|---|---|---|
| Prior 424 records | fd5a1449c94a16c9 | YES |
| Prior 448 records (6E baseline) | 3339ca09d11feba6 | STABLE |

## Sources Fetched vs Skipped

### Live-fetched (official_taxonomy_doc, authority_tier=A) — 22 records

| Source | URL | Status |
|---|---|---|
| MITRE CWE overview | cwe.mitre.org/about/index.html | OK |
| CWE-79 XSS | cwe.mitre.org/data/definitions/79.html | OK |
| CWE-89 SQL Injection | cwe.mitre.org/data/definitions/89.html | OK |
| CWE-352 CSRF | cwe.mitre.org/data/definitions/352.html | OK |
| CWE-22 Path Traversal | cwe.mitre.org/data/definitions/22.html | OK |
| CWE-78 Command Injection | cwe.mitre.org/data/definitions/78.html | OK |
| CWE-918 SSRF | cwe.mitre.org/data/definitions/918.html | OK |
| CWE-200 Info Exposure | cwe.mitre.org/data/definitions/200.html | OK |
| CWE-287 Improper Auth | cwe.mitre.org/data/definitions/287.html | OK |
| CWE-798 Hardcoded Creds | cwe.mitre.org/data/definitions/798.html | OK |
| CWE-522 Protected Creds | cwe.mitre.org/data/definitions/522.html | OK |
| CWE-611 XXE | cwe.mitre.org/data/definitions/611.html | OK |
| CWE-614 Cookie/Secure | cwe.mitre.org/data/definitions/614.html | OK |
| CWE-1004 Cookie/HttpOnly | cwe.mitre.org/data/definitions/1004.html | OK |
| CWE-1021 Clickjacking | cwe.mitre.org/data/definitions/1021.html | OK |
| CWE-693 Protection Failure | cwe.mitre.org/data/definitions/693.html | OK |
| NVD CVSS reference | nvd.nist.gov/vuln-metrics/cvss | OK |
| NVD API start-here | nvd.nist.gov/developers/start-here | OK |
| CVSS v3.1 | first.org/cvss/v3-1/ | OK |
| CVSS v4.0 | first.org/cvss/v4-0/ | OK |
| OWASP Risk Rating | owasp.org/www-community/OWASP_Risk_Rating_Methodology | OK |
| OWASP Top 10 | owasp.org/Top10/2021/ (A01 live; A02-A10 authored) | Partial |

### Skipped / Authored (internal_doc, authority_tier=B) — 2 normalized files

| Source | Reason |
|---|---|
| CVE Program (cve.org/About/Overview) | JS-heavy SPA; page returned no content |
| CISA KEV catalog (cisa.gov/known-exploited...) | HTTP 403 on both URLs |

### Additional pages not fetched per spec limits
| Source | Reason |
|---|---|
| cve.org/About/Process etc (5 CVE pages) | SPA; all returned blank |
| nvd.nist.gov/general/faq | Page returned navigation only |
| OWASP A02-A10 individual pages | Main page redirected; authored A02-A10 in summary file |
| CISA KEV JSON feed | EXPLICITLY excluded per Phase 6F hard limits |

## Normalized Files Created (24 files)

**`corpus/normalized/vulnerability-taxonomy/cwe/`** — 16 files:
CWE overview + 15 individual CWE definition extracts

**`corpus/normalized/vulnerability-taxonomy/`** — 8 files:
- `cve/pd-vt-cve--program.md` (authored)
- `nvd/pd-vt-nvd--cvss.md`, `nvd/pd-vt-nvd--api.md`
- `cvss/pd-vt-cvss--v31.md`, `cvss/pd-vt-cvss--v40.md`
- `cisa-kev/pd-vt-cisa-kev--catalog.md` (authored)
- `owasp/pd-vt-owasp--risk-rating.md`, `owasp/pd-vt-owasp--top10.md`

## Knowledge Files Created

**`knowledge/vulnerability-taxonomy/`** — 8 READMEs + 15 per-CWE notes + 15 synthesis notes:

### 15 Focused CWE Notes
CWE-79 XSS, -89 SQLi, -352 CSRF, -22 Path Traversal, -78 Command Injection,
-918 SSRF, -200 Info Exposure, -287 Improper Auth, -522 Protected Creds,
-611 XXE, -798 Hardcoded Creds, -614 Cookie/Secure, -1004 Cookie/HttpOnly,
-1021 Clickjacking, -693 Protection Failure

### 15 Synthesis/Policy Notes
- vulnerability-taxonomy-overview.md
- cve-vs-cwe-vs-nvd.md
- cvss-severity-model.md
- cvss-v31-vs-v40.md
- exploitability-vs-impact.md
- severity-vs-confidence.md
- cisa-kev-known-exploited-model.md
- owasp-risk-rating-model.md
- owasp-top-10-mapping.md
- webhound-finding-taxonomy.md (scanner finding -> CWE/OWASP/severity table)
- webhound-cwe-mapping.md (direct CWE assignments per finding type)
- webhound-cvss-usage-policy.md
- when-not-to-assign-cve.md
- customer-safe-vulnerability-language.md
- wade-taxonomy-relevance.md

## Chunks

| File | Chunks |
|---|---|
| `vuln_taxonomy_chunks.jsonl` | 56 |
| CWE sources | 18 |
| OWASP sources | 4 |
| NVD | 3 |
| CVSS | 3 |
| CISA KEV / CVE (authored) | 4 |
| Synthesis notes | 24 |

## Retrieval Self-Tests (22 of 22 passed)

All 22 tests in `tests/ai/test_vuln_taxonomy.py` — all passed.

| # | Topic | Pass |
|---|---|---|
| 1 | CVE vs CWE | PASS |
| 2 | NVD role vs CVE | PASS |
| 3 | How WebHound should use CVSS | PASS |
| 4 | Severity vs confidence | PASS |
| 5 | When NOT to assign a CVE | PASS |
| 6 | CWE for XSS | PASS |
| 7 | CWE for SQLi | PASS |
| 8 | CWE for CSRF | PASS |
| 9 | CWE for SSRF | PASS |
| 10 | CWE for hardcoded credentials | PASS |
| 11 | CWE for insecure cookie flags | PASS |
| 12 | OWASP Top 10 for injection | PASS |
| 13 | OWASP Top 10 for security misconfiguration | PASS |
| 14 | How WADE should use CISA KEV | PASS |
| 15 | How to explain missing CSP | PASS |
| 16 | How to explain exposed .env | PASS |
| 17 | How to explain third-party script risk | PASS |
| 18 | How to avoid overstating threat-intel findings | PASS |
| 19 | How to map provider-blocked scans | PASS |
| 20 | How to map Nuclei/ZAP external findings | PASS |
| 21 | How customer reports should describe severity | PASS |
| 22 | How WADE combines taxonomy with evidence | PASS |

Plus 4 structural validation tests (schema, manifest count, chunks, CWE files).

## Full Test Suite

```
85 passed, 0 failed (in ~5.4s)
```
(59 pre-6F + 26 Phase 6F tests)

## Invariant Checks

| Check | Result |
|---|---|
| Prior 424 records byte-stable | YES |
| Prior 448 records byte-stable | YES |
| Duplicate doc_ids | 0 |
| Forbidden tokens (secrets/API keys) | 0 real (2 false positives: "risk-" contains "sk-" substring) |
| .mcp.json unchanged (claude-flow only) | YES |
| scanner/ changes | NONE |
| WADE/provider-access changes | NONE |
| apps/ source changes | NONE |
| Files > 500 lines | NONE (test_knowledge_structure.py was already 532 — Phase 6F tests in separate file) |
| Raw NVD/CVE bulk dumps | NONE |
| KEV JSON feed in repo | NONE |
| Customer/private scan data | NONE |

## Schema Changes

`corpus/manifests/manifest.schema.json`: Added `"official_taxonomy_doc"` to `source_type` enum.

## WebHound Finding Taxonomy Summary

Documented mapping for 28+ scanner finding categories including:
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Cookie flags (Secure, HttpOnly, SameSite)
- Sensitive file exposure (.env, .git, backup, admin paths)
- Third-party script risks (TI match, SRI, obfuscation)
- Active validation findings (Nuclei CVE, ZAP passive)
- Infrastructure exposure (GraphQL, Swagger, WordPress, TLS, DNS)

## CVE/CWE/CVSS Policy Summary

- CVE: assign ONLY when scanner identifies specific vulnerable product+version with published CVE
- CWE: assign to finding category (class-level acceptable); 15 CWE mappings documented
- CVSS: use ONLY for CVE-linked findings (NVD scores); never compute CVSS for misconfigs
- OWASP Risk Rating: use for non-CVE findings (scanner misconfigurations and weaknesses)
- CISA KEV: escalation signal — "actively exploited" label when CVE confirmed in KEV
- Missing headers: NOT CVEs; report as CWE + OWASP category

## WADE Taxonomy Relevance Summary

- MUST NOT: assign CVE to missing-header/misconfiguration findings
- MUST NOT: display CVSS for non-CVE findings in reports
- MUST NOT: report "vulnerability" when finding is a hardening gap
- SHOULD: assign CWE to every finding with >=0.7 confidence
- SHOULD: include OWASP Top 10 category in customer report context
- SHOULD: check KEV status when a CVE is confirmed by scanner/Nuclei
- SHOULD: track severity and confidence as independent dimensions

## Licensing Notes

1. **MITRE CWE**: Free for research/education/tools per CWE terms of use; attribution recommended.
2. **NIST NVD**: Public domain; required attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
3. **FIRST CVSS**: Free to use and reference; specification owned by FIRST.Org.
4. **OWASP**: CC-BY-SA 3.0; attribution required for content reuse.
5. **CISA**: Government materials, public domain; authored synthesis only (403 block).
6. **CVE Program**: Public disclosure; authored synthesis only (SPA block).

## Known Gaps

- CVE program pages (cve.org) not machine-readable (JS SPA)
- CISA KEV catalog overview page (403); authored synthesis covers key concepts
- OWASP Top 10 individual category pages (A02-A10) not individually fetched; summarized
- NVD FAQ page returned only navigation HTML

## Next-Phase Recommendation

Phase 6G could cover:
- Web-framework-specific vulnerability knowledge (Django/Flask/Express/WordPress)
- Browser security model (SOP, CORS, CSP level 2/3 directives, Feature Policy)
- TLS/PKI deep dive (cert transparency, HPKP, DANE)
- Supply chain security (npm/PyPI malicious package patterns)
All subject to the same hard limits: no bulk CVE/NVD feeds, no exploit databases.
