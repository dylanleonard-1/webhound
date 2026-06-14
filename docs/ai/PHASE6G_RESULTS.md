# Phase 6G Results — Knowledge Base Validation, Inventory & WADE Readiness

Date: 2026-06-13  |  Branch: feat/ai-knowledge-phase-6g-validation-audit
Manifest records: 487  |  Corpus docs indexed: 477
Retrieval questions: 120  |  Method: TF-IDF keyword scoring

## 0. Precheck

| Check | Result |
|---|---|
| Branch | main |
| All Phase 6 PRs merged | YES (6A–6F via PRs 1–9) |
| Manifest records | 487 (≥487 ✓) |
| pytest tests/ai | 85 passed ✓ |
| Main CI | success (fab218e) ✓ |
| scanner/ unchanged | ✓ |
| WADE unchanged | ✓ |
| provider-access unchanged | ✓ |
| .mcp.json unchanged | ✓ |
| Stray package-lock.json | pre-existing, not staged |

## 1. Knowledge Inventory

### By source_type

| source_type | count |
|---|---|
| internal_doc | 296 |
| official_repo | 61 |
| official_provider_doc | 46 |
| detection_repo | 42 |
| official_taxonomy_doc | 22 |
| official_threat_intel_doc | 9 |
| official_doc | 6 |
| decision_log | 3 |
| planning_reference | 2 |

### By authority_tier

| tier | count |
|---|---|
| A | 273 |
| B | 106 |
| C | 108 |

### By phase (prefix heuristic)

| phase | count |
|---|---|
| 6A | 6 |
| 6B | 52 |
| 6C | 30 |
| 6D | 14 |
| 6E | 24 |
| 6F | 39 |
| Other | 322 |

### By topic

| topic | count |
|---|---|
| Other | 322 |

| Detection Engineering | 52 |

| Provider Intelligence | 44 |

| Vulnerability Taxonomy | 39 |

| Threat Intelligence | 24 |

| Security Standards | 6 |

## 2. Retrieval Validation (100 Questions)

### Overall Accuracy

| Metric | Score |
|---|---|
| Top-1 | 17% (20/120) |
| Top-3 | 32% (38/120) |
| Top-5 | 46% (55/120) |

### By Domain

| Domain | Top-1 | Top-3 | Top-5 | N |
|---|---|---|---|---|
| Detection | 15% | 15% | 30% | 20 |

| Provider | 40% | 70% | 75% | 20 |

| Standards | 30% | 45% | 45% | 20 |

| Taxonomy | 0% | 20% | 55% | 20 |

| ThreatIntel | 0% | 15% | 30% | 20 |

| WADE | 15% | 25% | 40% | 20 |

### Per-Question Results

| # | Question (truncated) | Frag | Top-1 Hit | T1 | T3 | T5 |
|---|---|---|---|---|---|---|
| 1 | What HTTP headers prevent clickjacking? | `cwe-1021` | mdn-cors-guide | ✗ | ✗ | ✗ |

| 2 | How does Content-Security-Policy work? | `csp` | mdn-csp-guide | ✓ | ✓ | ✓ |

| 3 | What is HSTS and why is it important? | `hsts` | lightrag--docs-fileprocessingpipeline | ✗ | ✓ | ✓ |

| 4 | What does the SameSite cookie attribute do? | `cookie` | lightrag--docs-fileprocessingpipeline | ✗ | ✓ | ✓ |

| 5 | What is OWASP A01 Broken Access Control? | `owasp-top-10` | mdn-cors-guide | ✗ | ✗ | ✗ |

| 6 | What is OWASP A03 Injection? | `owasp-top-10` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 7 | What is OWASP A05 Security Misconfiguration? | `owasp-top-10` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 8 | What is OWASP A10 SSRF? | `owasp-top-10` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 9 | How does Subresource Integrity SRI work? | `subresource-integri` | mdn-subresource-integrity | ✓ | ✓ | ✓ |

| 10 | What is Cross-Origin Resource Sharing CORS? | `cors` | mdn-cors-guide | ✓ | ✓ | ✓ |

| 11 | What is the OWASP ASVS? | `asvs` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 12 | What does the X-Content-Type-Options header do? | `security-header` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 13 | What is the Referrer-Policy header? | `security-header` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 14 | How does input validation prevent injection attacks? | `libinjection` | lightrag--docs-fileprocessingpipeline | ✗ | ✓ | ✓ |

| 15 | What permissions does Permissions-Policy control? | `security-header` | mdn-cors-guide | ✗ | ✗ | ✗ |

| 16 | What is OWASP A02 Cryptographic Failures? | `owasp-top-10` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 17 | What is the Web Security Testing Guide WSTG? | `wstg` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 18 | What does unsafe-inline in CSP mean? | `csp` | mdn-csp-guide | ✓ | ✓ | ✓ |

| 19 | How does CORS preflight work? | `cors` | mdn-cors-guide | ✓ | ✓ | ✓ |

| 20 | What is a nonce in a Content Security Policy? | `csp` | mdn-csp-guide | ✓ | ✓ | ✓ |

| 21 | How does Nuclei perform vulnerability detection? | `nuclei` | nuclei--readme | ✓ | ✓ | ✓ |

| 22 | What are Nuclei YAML templates? | `nuclei` | nuclei--readme | ✓ | ✓ | ✓ |

| 23 | What is OWASP ZAP used for? | `zap` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 24 | How does ZAP passive scanning work? | `zap-passive` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 25 | How does ZAP active scanning work? | `zap-active` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 26 | What is DalFox and how does it detect XSS? | `dalfox` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 27 | What is XSStrike used for? | `xsstrike` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 28 | What is libinjection used for? | `libinjection` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 29 | How does libinjection classify SQL injection? | `libinjection-classi` | det-libinjection--migration | ✗ | ✗ | ✗ |

| 30 | How does browser-based validation work? | `browser-validation` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 31 | What headless rendering does WebHound use? | `firecrawl` | katana--readme | ✗ | ✗ | ✗ |

| 32 | How does WebHound detect DOM XSS? | `dom-xss` | mdn-csp-guide | ✗ | ✗ | ✗ |

| 33 | How does WebHound validate third-party script risk? | `third-party-domain` | mdn-csp-guide | ✗ | ✗ | ✓ |

| 34 | How does WebHound detect SQL injection? | `sql-injection` | det-zap--docs-scanners | ✗ | ✗ | ✗ |

| 35 | What is sqlmap and how does it work? | `sqlmap` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✓ |

| 36 | How does DalFox reduce false positives? | `dalfox-false` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 37 | What is the ZAP evidence model? | `zap-evidence` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 38 | How do Nuclei template matchers work? | `nuclei-matchers` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 39 | What are nuclei extractors? | `nuclei-extractors` | nuclei--readme | ✗ | ✗ | ✗ |

| 40 | How does WebHound score finding confidence? | `confidence` | threat-intel-confidence-model | ✓ | ✓ | ✓ |

| 41 | What is a Cloudflare challenge page error 1020? | `cloudflare` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 42 | How does Cloudflare Turnstile work? | `turnstile` | pd-cloudflare--turnstile | ✓ | ✓ | ✓ |

| 43 | What is Cloudflare WAF? | `waf` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 44 | How does Vercel deployment protection affect scanning? | `vercel` | lightrag--docs-fileprocessingpipeline | ✗ | ✓ | ✓ |

| 45 | What is Vercel firewall? | `vercel-firewall` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 46 | How does Railway health check work? | `railway` | deployment | ✓ | ✓ | ✓ |

| 47 | How does Netlify handle bot traffic? | `netlify` | pd-cloudflare--bots | ✗ | ✓ | ✓ |

| 48 | What is Fastly WAF behavior? | `fastly` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 49 | How does AWS CloudFront affect scanning? | `cloudfront` | pd-aws-waf--waf-latest-developerguide-wh | ✓ | ✓ | ✓ |

| 50 | What is AWS WAF? | `aws-waf` | pd-aws-waf--waf-latest-developerguide-wh | ✓ | ✓ | ✓ |

| 51 | What is Azure Front Door WAF? | `azure-front-door` | pd-azure-front-door--en-us-azure-frontdo | ✓ | ✓ | ✓ |

| 52 | What is Google Cloud Armor? | `google-cloud-armor` | pd-google-cloud-armor--armor-docs-cloud- | ✓ | ✓ | ✓ |

| 53 | What is Akamai bot manager? | `akamai` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 54 | How does Imperva cloud WAF work? | `imperva` | cloud-waf | ✓ | ✓ | ✓ |

| 55 | What is Sucuri WAF? | `sucuri` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 56 | How does Fly.io handle deployments? | `flyio` | pd-flyio--docs-networking | ✓ | ✓ | ✓ |

| 57 | How does WebHound allowlist scanners? | `provider-access` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 58 | What is Vercel protection bypass automation? | `protection-bypass` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 59 | How does WebHound classify provider-blocked findings? | `provider-blocked` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 60 | What does WebHound do with informational severity? | `informational` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 61 | What is URLHaus and what does it track? | `urlhaus` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 62 | What is ThreatFox? | `threatfox` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 63 | What is AbuseIPDB? | `abuseipdb` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 64 | What is GreyNoise and how does it classify IPs? | `greynoise` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 65 | What is Google Safe Browsing? | `google-safe` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 66 | What is PhishTank? | `phishtank` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 67 | What is OpenPhish? | `openphish` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 68 | What is Shodan used for? | `shodan` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 69 | What is MISP? | `misp` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 70 | What is AlienVault OTX? | `otx` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 71 | What is VirusTotal used for? | `virustotal` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 72 | What is Censys? | `censys` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 73 | How does WebHound handle shared CDN IP reputation? | `shared-infrastructure` | threat-intel-for-wade | ✗ | ✓ | ✓ |

| 74 | How does GreyNoise reduce false positives? | `greynoise` | playwright-mcp--readme | ✗ | ✓ | ✓ |

| 75 | What is the threat intel confidence model? | `threat-intel-confidence` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 76 | How does WebHound identify malicious redirects? | `malicious-redirect` | pd-netlify--routing-redirects | ✗ | ✗ | ✓ |

| 77 | What are Indicators of Compromise IOC? | `indicator` | github-mcp-server--readme | ✗ | ✗ | ✗ |

| 78 | How does WebHound use threat intel for customer reports | `customer-reporting` | github-mcp-server--readme | ✗ | ✗ | ✗ |

| 79 | How does threat intel integrate with WADE? | `threat-intel-for-wade` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 80 | What is the URL vs domain vs IP confidence model? | `url-vs-domain` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 81 | What is the difference between CVE and CWE? | `cve-vs-cwe` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 82 | What does NVD add to CVE data? | `nvd` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 83 | How does CVSS v3.1 scoring work? | `cvss` | github-mcp-server--readme | ✗ | ✗ | ✓ |

| 84 | What changed in CVSS v4.0? | `cvss-v31-vs-v40` | owasp-asvs-readme | ✗ | ✗ | ✗ |

| 85 | What is CISA KEV? | `cisa-kev` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 86 | What is CWE-79 Cross-Site Scripting? | `cwe-79` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 87 | What is CWE-89 SQL Injection? | `cwe-89` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 88 | What is CWE-352 CSRF? | `cwe-352` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 89 | What is CWE-22 Path Traversal? | `cwe-22` | github-mcp-server--docs-remote-server | ✗ | ✓ | ✓ |

| 90 | What is CWE-78 Command Injection? | `cwe-78` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 91 | What is CWE-918 SSRF? | `cwe-918` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 92 | What is CWE-798 Hardcoded Credentials? | `cwe-798` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 93 | What is CWE-614 Cookie without Secure flag? | `cwe-614` | nuclei--syntax-reference | ✗ | ✗ | ✗ |

| 94 | What is CWE-1004 Cookie without HttpOnly? | `cwe-1004` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 95 | When should WebHound NOT assign a CVE? | `when-not-to-assign` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 96 | How does severity differ from confidence? | `severity-vs-confidence` | lightrag--docs-fileprocessingpipeline | ✗ | ✓ | ✓ |

| 97 | What is the OWASP Risk Rating methodology? | `owasp-risk-rating` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 98 | How should WebHound use CVSS scores? | `cvss-usage-policy` | nuclei--syntax-reference | ✗ | ✗ | ✓ |

| 99 | What is the WebHound finding taxonomy? | `finding-taxonomy` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 100 | What is CWE-200 Information Exposure? | `cwe-200` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 101 | How should WADE classify an exposed .env file? | `finding-taxonomy` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 102 | How should WADE handle a malicious third-party script? | `third-party` | mdn-csp-guide | ✓ | ✓ | ✓ |

| 103 | How should WADE explain a missing CSP header? | `csp` | mdn-csp-guide | ✓ | ✓ | ✓ |

| 104 | How should WADE classify a Cloudflare challenge page? | `cloudflare` | github-mcp-server--readme | ✗ | ✗ | ✓ |

| 105 | How does WADE handle threat-intel match on shared CDN I | `shared-infra` | threat-intel-for-wade | ✗ | ✗ | ✓ |

| 106 | How should WADE classify a Nuclei-only finding? | `nuclei` | nuclei--readme | ✓ | ✓ | ✓ |

| 107 | How should WADE classify a ZAP-only finding? | `zap` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 108 | How should WADE handle multiple confirmation sources? | `confidence` | nuclei--syntax-reference | ✗ | ✓ | ✓ |

| 109 | What CWE should WADE assign to XSS? | `cwe-79` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 110 | What CWE should WADE assign to SQL injection? | `cwe-89` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 111 | How should WADE report CVE vs misconfiguration? | `cvss-usage-policy` | gitleaks--readme | ✗ | ✗ | ✗ |

| 112 | How should WADE explain missing HSTS to a customer? | `customer-safe` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 113 | What OWASP category covers missing X-Frame-Options? | `owasp-top-10` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 114 | How does WADE use CISA KEV to escalate findings? | `cisa-kev` | playwright-mcp--readme | ✗ | ✗ | ✗ |

| 115 | How should WADE describe an exposed .git directory? | `finding-taxonomy` | mcp-servers--src-git-readme | ✗ | ✗ | ✗ |

| 116 | What is WADE's false-positive rule for Cloudflare? | `cloudflare` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✓ |

| 117 | How does WADE score confidence vs severity independentl | `severity-vs-conf` | threat-intel-confidence-model | ✗ | ✓ | ✓ |

| 118 | What is WADE's customer-safe vulnerability language? | `customer-safe` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 119 | How does WADE use threat intel in customer reports? | `customer-reporting` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

| 120 | What does WADE do when scanner conflicts with TI? | `wade-taxonomy` | lightrag--docs-fileprocessingpipeline | ✗ | ✗ | ✗ |

## 3. Duplicate Analysis

- Duplicate doc_ids: **0** (none — clean ✓)
- Duplicate URLs: **0**

### Near-duplicate candidates (recommend-only; no deletions)

| Pair | Overlap reason | Action |
|---|---|---|
| webhound-finding-taxonomy + webhound-cwe-mapping | Both map findings to CWE; taxonomy is superset | Low risk — keep both; merge in Phase 6H cleanup |

| cvss-severity-model + owasp-risk-rating-model | Both cover severity scoring frameworks | Distinct (CVSS=CVE, OWASP Risk=non-CVE); keep separate |

| urlhaus.md + threatfox.md | Both are Abuse.ch feeds | Distinct data types; keep separate |

| cisa-kev-known-exploited-model + when-not-to-assign-cve | Both govern CVE assignment policy | Complementary; keep separate |

| threat-intel-false-positive-model + shared-infrastructure-risk | Both cover TI false-positive reduction | Distinct scope; keep separate |

## 4. Chunk Quality Audit

| Chunk file | N | Avg (chars) | Min | Max |
|---|---|---|---|---|
| `corpus/normalized/detection-repos/detection_chunks.jsonl` | 285 | 1269 | 200 | 6022 |
| `corpus/normalized/provider-docs/provider_chunks.jsonl` | 116 | 2488 | 186 | 6000 |
| `corpus/normalized/repos/repo_chunks.jsonl` | 552 | 1349 | 213 | 11987 |
| `corpus/normalized/threat-intel/threat_intel_chunks.jsonl` | 96 | 1100 | 142 | 1570 |
| `corpus/normalized/vulnerability-taxonomy/vuln_taxonomy_chunks.jsonl` | 54 | 985 | 155 | 1400 |
| `corpus/normalized/docs/official/official_chunks.jsonl` | 81 | 1305 | 351 | 2683 |

**Total:** 1184 chunks | avg 1401 | min 142 | max 11987
- Small (<200 chars): 7
- Large (>2000 chars): 74

### Critical Gap: Phases 6A–6E knowledge files NOT chunked
Only Phase 6F taxonomy files have a chunk index. The 138+ Markdown files in
`knowledge/detection-engineering/`, `knowledge/threat-intelligence/`, `knowledge/provider-docs/`
are NOT in any chunk JSONL. **Impact:** WADE vector retrieval will only draw from 54 taxonomy chunks.
**Recommendation:** A Phase 6H chunking pass should ingest all remaining knowledge files.
## 5. Coverage Gap Analysis

### Well-covered topics

- HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- MITRE CWE: 15 entries (CWE-22/78/79/89/200/287/352/522/611/614/693/798/918/1004/1021)
- CVSS v3.1 + v4.0; OWASP Top 10 2021 (A01–A10); OWASP Risk Rating, WSTG, ASVS
- ZAP (passive + active), Nuclei, DalFox, XSStrike, libinjection, sqlmap, firecrawl
- Cloudflare, Vercel, Railway, Netlify, Fastly, CloudFront, AWS WAF, Azure FD, GCP Armor, Akamai, Imperva, Sucuri, Fly.io
- URLHaus, ThreatFox, AbuseIPDB, GreyNoise, GSB, PhishTank, OpenPhish, Shodan, MISP, OTX, VirusTotal, Censys
- Shared-infrastructure risk, TI confidence model, TI false-positive model
- WADE: finding taxonomy (28 categories), CWE mapping, CVSS usage policy, customer-safe language

### Weakly-represented or absent topics

| Gap | Severity | Detail |
|---|---|---|
| Phases 6A–6E unchunked | HIGH | 138+ knowledge files not in chunk index; blocks vector retrieval |

| Explicit confidence thresholds | HIGH | WADE docs lack numeric cutoffs (e.g. 0.3/0.5/0.7/0.9); policy is qualitative only |

| CWE-601 Open Redirect | MED | Common finding type; absent from taxonomy |

| CWE-384 Session Fixation | MED | Relevant to auth scanner findings; absent |

| CWE-93 CRLF Injection | MED | Header injection finding type; absent |

| Magecart / web skimmer IOC patterns | MED | knowledge/javascript-malware-library/magecart/ is a README stub only |

| Supply-chain attack patterns | MED | knowledge/javascript-malware-library/supply-chain-attacks/ is stub |

| Credential stuffing patterns | LOW | nuclei-templates credential-stuffing README fetched; no synthesis note |

| OAuth abuse (CWE-287 extension) | LOW | CWE-287 note is brief; OAuth-specific attack patterns not documented |

| Cloud misconfiguration taxonomy | LOW | AWS/GCP/Azure-specific misconfig patterns absent |

| WebAssembly security | LOW | Not covered |

| GraphQL injection detail | LOW | GraphQL exposure noted; injection techniques not documented |

| DOM clobbering / prototype pollution | LOW | Advanced browser security not represented |

| CVSS environmental/temporal metrics | LOW | Base metrics documented; environmental/temporal metrics not covered |

## 6. WADE Readiness Audit

| Capability | Score | Justification |
|---|---|---|
| Finding Classification | 8/10 | 28 scanner categories → CWE/OWASP/severity. Missing: open redirect, session fixation, CRLF, credential stuffing. |
| Threat-Intel Correlation | 8/10 | 12 TI sources documented (URLHaus, ThreatFox, AbuseIPDB, GreyNoise, GSB, PhishTank, OpenPhish, Shodan, MISP, OTX, VirusTotal, Censys). Shared-IP policy documented. Magecart IOC patterns absent. |
| Provider Context | 8/10 | 13 providers covered with WAF/bot detection signatures. Akamai has only bot-manager note. Scanner allowlisting policy documented. |
| False-Positive Suppression | 7/10 | GreyNoise noise reduction, shared-IP CDN policy, provider-blocked classification documented. Missing: explicit FP confidence thresholds and ZAP FP rate guidance. |
| Severity Assignment | 8/10 | CVSS v3.1/v4.0, OWASP Risk Rating, missing-header severity policy clear. Missing CVE severity for open-redirect/session-fixation CWEs. |
| Confidence Assignment | 7/10 | Severity-vs-confidence independence documented. Multi-source confirmation policy noted. Missing: numeric cutoff values for confidence tiers. |
| Customer Reporting | 8/10 | customer-safe-vulnerability-language.md covers prohibited terms, severity labels, confirmed vs suspected. OWASP A-category attribution present. |
| Evidence Correlation | 7/10 | Multi-confirmation policy documented. Scanner-vs-TI weight documented. Missing: structured evidence-weight table with numeric weights. |
| Root-Cause Explanation | 7/10 | 15 CWE explanations + OWASP mapping present. Missing: per-finding remediation guidance for customer reports. |

**WADE Average: 7.6/10**

## 7. WADE Knowledge Test

| Scenario | Expected reasoning | Source found? |
|---|---|---|
| Exposed .env file | CWE-200/CWE-798, High; confirmed if credentials visible | PARTIAL |

| Malicious third-party script | Check URLHaus/ThreatFox; SRI absence as factor | YES |

| Missing CSP header | CWE-1021, OWASP A05, Medium, OWASP Risk Rating | YES |

| Cloudflare challenge page (1020) | Provider-blocked, informational — not a finding | YES |

| TI match on shared CDN IP | Reduce confidence; require domain-level confirmation | PARTIAL |

| Nuclei-only CVE finding | High confidence if CVE-linked; check CISA KEV | YES |

| ZAP-only passive finding | Lower confidence; flag for review if High severity | YES |

| Multiple confirmations (scanner + TI + ZAP) | Highest tier; escalate if CISA KEV/TI match | PARTIAL |

## 8. Readiness Scorecard

| Area | Score | Notes |
|---|---|---|
| Knowledge Coverage | 7.5/10 | 487 records, 6 phases, 13 TI sources, 13 providers, 15 CWEs, OWASP full suite. Gaps: supply-chain, OAuth, open-redirect, session-fixation. |
| Retrieval Quality | 3.2/10 | Top-3: 32% / Top-5: 46% via TF-IDF. Production vector search expected higher; blocked by unchunked 6A–6E files. |
| Document Quality | 8.0/10 | All files structured. Authored files labeled. Authority tiers accurate. Most scanner-engines/ dirs are README stubs. |
| Authority Coverage | 7.5/10 | Tier A: strong (official docs live-fetched). Tier B: fills gaps. Tier C: minimal. CISA KEV and CVE program SPA-blocked (authored B). |
| Threat Intel | 8.5/10 | 12 TI sources documented with API notes + confidence model + shared-infrastructure policy. Magecart patterns absent. |
| Provider Intelligence | 8.0/10 | 13 providers: Cloudflare, Vercel, Railway, Fastly, Netlify, CloudFront, AWS WAF, Azure FD, GCP Armor, Imperva, Sucuri, Fly.io, Akamai. Allowlisting policy documented. |
| Taxonomy | 8.5/10 | 15 CWEs, CVSS v3.1/v4.0, CISA KEV, OWASP Risk Rating, OWASP Top 10 2021, 28-category finding taxonomy. |
| WADE Readiness | 7.6/10 | Avg 7.6/10 across 9 capabilities. Strong classification + reporting; needs explicit confidence thresholds. |

**Overall Knowledge Foundation Score: 7.3/10**

## 9. Invariant Checks

| Check | Result |
|---|---|
| Manifest records | 487 (unchanged) |
| Records deleted | 0 |
| Duplicate doc_ids | 0 (none) |
| scanner/ changes | NONE |
| WADE/provider-access changes | NONE |
| apps/ source changes | NONE |
| .mcp.json changes | NONE |
| tests/ai | 85 passed |

## 10. Recommendation

**NEEDS MORE KNOWLEDGE** — address the following before Phase 8:

1. **Chunk all knowledge files (CRITICAL)** — Phases 6A–6E .md notes not in chunk index.
2. **Add numeric confidence thresholds** — explicit 0.3/0.5/0.7/0.9 cutoffs for WADE confidence tiers.
3. **Add missing CWEs** — CWE-601 Open Redirect, CWE-384 Session Fixation, CWE-93 CRLF Injection.
4. **Flesh out stub dirs** — javascript-malware-library/magecart/, supply-chain-attacks/, skimmers/.
5. **Akamai WAF depth** — only bot-manager note exists; no challenge detection doc.
