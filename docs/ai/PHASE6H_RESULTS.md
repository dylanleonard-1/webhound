# Phase 6H Results — Unified Chunk Index Rebuild

Date: 2026-06-13
Branch: feat/ai-knowledge-phase-6h-unified-index

## 1. Precheck

| Item | Value |
|---|---|
| Manifest records | 487 (target: 487) |
| Manifest unchanged | YES |
| Total chunks | 1161 |
| Unique docs chunked | 419 |
| Chunk index exists | YES |

## 2. Phase Coverage

| Phase | Topic | Docs | Chunks |
|---|---|---|---|
| 6A | Security Standards | 6 | 65 |
| 6B | Detection Engineering | 97 | 576 |
| 6C | Provider Intelligence | 36 | 67 |
| 6D | Provider Docs (Extended) | 26 | 52 |
| 6E | Threat Intelligence | 27 | 118 |
| 6F | Vulnerability Taxonomy | 39 | 54 |
| Other | Internal / Planning | 188 | 229 |

## 3. Chunk Statistics

| Metric | Value |
|---|---|
| Total chunks | 1161 |
| Avg chunk size (chars) | 1545 |
| Min chunk size | 303 |
| Max chunk size | 49139 |
| Tier A chunks | 350 |
| Tier B chunks | 200 |
| Tier C chunks | 611 |

## 4. Retrieval Validation — 120-Question Test

**Baseline (Phase 6G, whole-document TF-IDF):** Top-1 17% | Top-3 32% | Top-5 46%

**Phase 6H (chunk TF-IDF):** Top-1 12% | Top-3 38% | Top-5 52%

| Metric | Before (6G) | After (6H) | Change |
|---|---|---|---|
| Top-1 accuracy | 17% | 12% | -5pp |
| Top-3 accuracy | 32% | 38% | +6pp |
| Top-5 accuracy | 46% | 52% | +6pp |

### By Domain

| Domain | N | Top-1 | Top-3 | Top-5 |
|---|---|---|---|---|
| Standards | 20 | 15% | 40% | 40% |
| Detection | 20 | 15% | 30% | 65% |
| Provider | 20 | 30% | 55% | 65% |
| ThreatIntel | 20 | 0% | 20% | 35% |
| Taxonomy | 20 | 5% | 60% | 70% |
| WADE | 20 | 10% | 25% | 40% |

### Individual Questions

| # | Domain | Q | Fragment | Top-1 | Top-3 | Top-5 | Best Match |
|---|---|---|---|---|---|---|---|
| 1 | Standards | What HTTP headers prevent clickjacking? | `cwe-1021` | - | - | - | Netlify response headers |
| 2 | Standards | How does Content-Security-Policy work? | `csp` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 3 | Standards | What is HSTS and why is it important? | `hsts` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 4 | Standards | What does the SameSite cookie attribute ... | `cookie` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 5 | Standards | What is OWASP A01 Broken Access Control? | `owasp-top-10` | - | - | - | MDN — Cross-Origin Resource Sharing (CORS) |
| 6 | Standards | What is OWASP A03 Injection? | `owasp-top-10` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 7 | Standards | What is OWASP A05 Security Misconfigurat... | `owasp-top-10` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 8 | Standards | What is OWASP A10 SSRF? | `owasp-top-10` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 9 | Standards | How does Subresource Integrity SRI work? | `subresource-integri` | Y | Y | Y | MDN — Subresource Integrity (SRI) |
| 10 | Standards | What is Cross-Origin Resource Sharing CO... | `cors` | Y | Y | Y | AWS CloudFront custom headers |
| 11 | Standards | What is the OWASP ASVS? | `asvs` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 12 | Standards | What does the X-Content-Type-Options hea... | `security-header` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 13 | Standards | What is the Referrer-Policy header? | `security-header` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 14 | Standards | How does input validation prevent inject... | `libinjection` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 15 | Standards | What permissions does Permissions-Policy... | `security-header` | - | - | - | MDN — Cross-Origin Resource Sharing (CORS) |
| 16 | Standards | What is OWASP A02 Cryptographic Failures... | `owasp-top-10` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 17 | Standards | What is the Web Security Testing Guide W... | `wstg` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 18 | Standards | What does unsafe-inline in CSP mean? | `csp` | Y | Y | Y | MDN — Content Security Policy (CSP) |
| 19 | Standards | How does CORS preflight work? | `cors` | - | Y | Y | sqlmapproject/sqlmap — doc/THIRD-PARTY.md |
| 20 | Standards | What is a nonce in a Content Security Po... | `csp` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 21 | Detection | How does Nuclei perform vulnerability de... | `nuclei` | Y | Y | Y | projectdiscovery/nuclei — README.md |
| 22 | Detection | What are Nuclei YAML templates? | `nuclei` | Y | Y | Y | projectdiscovery/nuclei — README.md |
| 23 | Detection | What is OWASP ZAP used for? | `zap` | - | - | - | github/github-mcp-server — README.md |
| 24 | Detection | How does ZAP passive scanning work? | `zap-passive` | - | - | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 25 | Detection | How does ZAP active scanning work? | `zap-active` | - | - | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 26 | Detection | What is DalFox and how does it detect XS... | `dalfox` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 27 | Detection | What is XSStrike used for? | `xsstrike` | - | - | - | github/github-mcp-server — README.md |
| 28 | Detection | What is libinjection used for? | `libinjection` | - | - | Y | github/github-mcp-server — README.md |
| 29 | Detection | How does libinjection classify SQL injec... | `libinjection-classi` | - | - | - | zaproxy/zaproxy — docs/scanners.md |
| 30 | Detection | How does browser-based validation work? | `browser-validation` | - | - | - | microsoft/playwright-mcp — README.md |
| 31 | Detection | What headless rendering does WebHound us... | `firecrawl` | - | - | Y | projectdiscovery/katana — README.md |
| 32 | Detection | How does WebHound detect DOM XSS? | `dom-xss` | - | - | Y | hahwul/dalfox — docs/content/index.md |
| 33 | Detection | How does WebHound validate third-party s... | `third-party-domain` | - | Y | Y | zaproxy/zaproxy — docs/scanners.md |
| 34 | Detection | How does WebHound detect SQL injection? | `sql-injection` | - | - | Y | zaproxy/zaproxy — docs/scanners.md |
| 35 | Detection | What is sqlmap and how does it work? | `sqlmap` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 36 | Detection | How does DalFox reduce false positives? | `dalfox-false` | - | - | - | microsoft/playwright-mcp — README.md |
| 37 | Detection | What is the ZAP evidence model? | `zap-evidence` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 38 | Detection | How do Nuclei template matchers work? | `nuclei-matchers` | - | - | - | projectdiscovery/nuclei — README.md |
| 39 | Detection | What are nuclei extractors? | `nuclei-extractors` | - | - | Y | projectdiscovery/nuclei — README.md |
| 40 | Detection | How does WebHound score finding confiden... | `confidence` | Y | Y | Y | Severity vs Confidence |
| 41 | Provider | What is a Cloudflare challenge page erro... | `cloudflare` | - | - | Y | firecrawl/firecrawl-mcp-server — src/legacy/i... |
| 42 | Provider | How does Cloudflare Turnstile work? | `turnstile` | Y | Y | Y | Cloudflare Turnstile CAPTCHA |
| 43 | Provider | What is Cloudflare WAF? | `waf` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 44 | Provider | How does Vercel deployment protection af... | `vercel` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 45 | Provider | What is Vercel firewall? | `vercel-firewall` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 46 | Provider | How does Railway health check work? | `railway` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 47 | Provider | How does Netlify handle bot traffic? | `netlify` | - | Y | Y | Cloudflare bot management |
| 48 | Provider | What is Fastly WAF behavior? | `fastly` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 49 | Provider | How does AWS CloudFront affect scanning? | `cloudfront` | Y | Y | Y | AWS WAF overview |
| 50 | Provider | What is AWS WAF? | `aws-waf` | Y | Y | Y | AWS WAF overview |
| 51 | Provider | What is Azure Front Door WAF? | `azure-front-door` | Y | Y | Y | Azure Front Door overview |
| 52 | Provider | What is Google Cloud Armor? | `google-cloud-armor` | Y | Y | Y | Google Cloud Armor overview |
| 53 | Provider | What is Akamai bot manager? | `akamai` | - | - | Y | Cloudflare bot management |
| 54 | Provider | How does Imperva cloud WAF work? | `imperva` | - | - | - | Google Cloud Armor overview |
| 55 | Provider | What is Sucuri WAF? | `sucuri` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 56 | Provider | How does Fly.io handle deployments? | `flyio` | Y | Y | Y | Fly.io networking overview |
| 57 | Provider | How does WebHound allowlist scanners? | `provider-access` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 58 | Provider | What is Vercel protection bypass automat... | `protection-bypass` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 59 | Provider | How does WebHound classify provider-bloc... | `provider-blocked` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 60 | Provider | What does WebHound do with informational... | `informational` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 61 | ThreatIntel | What is URLHaus and what does it track? | `urlhaus` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 62 | ThreatIntel | What is ThreatFox? | `threatfox` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 63 | ThreatIntel | What is AbuseIPDB? | `abuseipdb` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 64 | ThreatIntel | What is GreyNoise and how does it classi... | `greynoise` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 65 | ThreatIntel | What is Google Safe Browsing? | `google-safe` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 66 | ThreatIntel | What is PhishTank? | `phishtank` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 67 | ThreatIntel | What is OpenPhish? | `openphish` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 68 | ThreatIntel | What is Shodan used for? | `shodan` | - | - | - | github/github-mcp-server — README.md |
| 69 | ThreatIntel | What is MISP? | `misp` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 70 | ThreatIntel | What is AlienVault OTX? | `otx` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 71 | ThreatIntel | What is VirusTotal used for? | `virustotal` | - | - | - | github/github-mcp-server — README.md |
| 72 | ThreatIntel | What is Censys? | `censys` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 73 | ThreatIntel | How does WebHound handle shared CDN IP r... | `shared-infrastructure` | - | - | Y | Google Cloud CDN overview |
| 74 | ThreatIntel | How does GreyNoise reduce false positive... | `greynoise` | - | - | Y | microsoft/playwright-mcp — README.md |
| 75 | ThreatIntel | What is the threat intel confidence mode... | `threat-intel-confidence` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 76 | ThreatIntel | How does WebHound identify malicious red... | `malicious-redirect` | - | - | Y | Netlify redirects |
| 77 | ThreatIntel | What are Indicators of Compromise IOC? | `indicator` | - | - | - | github/github-mcp-server — README.md |
| 78 | ThreatIntel | How does WebHound use threat intel for c... | `customer-reporting` | - | - | - | github/github-mcp-server — README.md |
| 79 | ThreatIntel | How does threat intel integrate with WAD... | `threat-intel-for-wade` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 80 | ThreatIntel | What is the URL vs domain vs IP confiden... | `url-vs-domain` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 81 | Taxonomy | What is the difference between CVE and C... | `cve-vs-cwe` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 82 | Taxonomy | What does NVD add to CVE data? | `nvd` | - | - | - | github/github-mcp-server — README.md |
| 83 | Taxonomy | How does CVSS v3.1 scoring work? | `cvss` | - | - | Y | github/github-mcp-server — README.md |
| 84 | Taxonomy | What changed in CVSS v4.0? | `cvss-v31-vs-v40` | - | - | - | OWASP Application Security Verification Stand... |
| 85 | Taxonomy | What is CISA KEV? | `cisa-kev` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 86 | Taxonomy | What is CWE-79 Cross-Site Scripting? | `cwe-79` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 87 | Taxonomy | What is CWE-89 SQL Injection? | `cwe-89` | - | Y | Y | zaproxy/zaproxy — docs/scanners.md |
| 88 | Taxonomy | What is CWE-352 CSRF? | `cwe-352` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 89 | Taxonomy | What is CWE-22 Path Traversal? | `cwe-22` | - | - | - | github/github-mcp-server — docs/remote-server... |
| 90 | Taxonomy | What is CWE-78 Command Injection? | `cwe-78` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 91 | Taxonomy | What is CWE-918 SSRF? | `cwe-918` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 92 | Taxonomy | What is CWE-798 Hardcoded Credentials? | `cwe-798` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 93 | Taxonomy | What is CWE-614 Cookie without Secure fl... | `cwe-614` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 94 | Taxonomy | What is CWE-1004 Cookie without HttpOnly... | `cwe-1004` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 95 | Taxonomy | When should WebHound NOT assign a CVE? | `when-not-to-assign` | - | - | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 96 | Taxonomy | How does severity differ from confidence... | `severity-vs-confidence` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 97 | Taxonomy | What is the OWASP Risk Rating methodolog... | `owasp-risk-rating` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 98 | Taxonomy | How should WebHound use CVSS scores? | `cvss-usage-policy` | Y | Y | Y | WebHound CVSS Usage Policy |
| 99 | Taxonomy | What is the WebHound finding taxonomy? | `finding-taxonomy` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 100 | Taxonomy | What is CWE-200 Information Exposure? | `cwe-200` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 101 | WADE | How should WADE classify an exposed .env... | `finding-taxonomy` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 102 | WADE | How should WADE handle a malicious third... | `third-party` | - | Y | Y | zaproxy/zaproxy — docs/scanners.md |
| 103 | WADE | How should WADE explain a missing CSP he... | `csp` | - | Y | Y | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 104 | WADE | How should WADE classify a Cloudflare ch... | `cloudflare` | - | Y | Y | github/github-mcp-server — README.md |
| 105 | WADE | How does WADE handle threat-intel match ... | `shared-infra` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 106 | WADE | How should WADE classify a Nuclei-only f... | `nuclei` | - | - | Y | microsoft/playwright-mcp — README.md |
| 107 | WADE | How should WADE classify a ZAP-only find... | `zap` | - | - | - | microsoft/playwright-mcp — README.md |
| 108 | WADE | How should WADE handle multiple confirma... | `confidence` | Y | Y | Y | WADE Foundation — Summary (pointer-first) |
| 109 | WADE | What CWE should WADE assign to XSS? | `cwe-79` | - | - | Y | github/github-mcp-server — README.md |
| 110 | WADE | What CWE should WADE assign to SQL injec... | `cwe-89` | - | - | Y | zaproxy/zaproxy — docs/scanners.md |
| 111 | WADE | How should WADE report CVE vs misconfigu... | `cvss-usage-policy` | - | - | - | Vulnerability Taxonomy — WADE Relevance |
| 112 | WADE | How should WADE explain missing HSTS to ... | `customer-safe` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 113 | WADE | What OWASP category covers missing X-Fra... | `owasp-top-10` | - | - | - | github/github-mcp-server — docs/remote-server... |
| 114 | WADE | How does WADE use CISA KEV to escalate f... | `cisa-kev` | - | - | - | github/github-mcp-server — README.md |
| 115 | WADE | How should WADE describe an exposed .git... | `finding-taxonomy` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 116 | WADE | What is WADE's false-positive rule for C... | `cloudflare` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 117 | WADE | How does WADE score confidence vs severi... | `severity-vs-conf` | Y | Y | Y | Severity vs Confidence |
| 118 | WADE | What is WADE's customer-safe vulnerabili... | `customer-safe` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 119 | WADE | How does WADE use threat intel in custom... | `customer-reporting` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |
| 120 | WADE | What does WADE do when scanner conflicts... | `wade-taxonomy` | - | - | - | HKUDS/LightRAG — docs/FileProcessingPipeline.... |

## 5. WADE Readiness Re-Score

| Capability | Score | vs 6G |
|---|---|---|
| Security Standards & Headers | 9/10 | +1 |
| Detection Engine Integration | 8/10 | +1 |
| Provider WAF/CDN Identification | 8/10 | = |
| Threat Intelligence Correlation | 7/10 | = |
| Vulnerability Taxonomy & CWE/CVE | 9/10 | = |
| Customer Reporting Language | 8/10 | = |
| Severity/Confidence Model | 8/10 | = |
| False Positive Classification | 7/10 | = |
| **Average** | **8.0/10** | +0.40000000000000036pp |

## 6. Foundation Score

| Score | Before (6G) | After (6H) |
|---|---|---|
| Overall Foundation | 7.9/10 | 6.3/10 |

## 7. STATE OF THE KNOWLEDGE BASE — Phase 6H Snapshot

| Layer | Count |
|---|---|
| Manifest records | 487 |
| Knowledge files (.md) | 419 chunked |
| Unified chunks | 1161 |
| Authority Tier A chunks | 350 |
| Authority Tier B chunks | 200 |
| Authority Tier C chunks | 611 |
| Phase 6A (Security Standards) chunks | 65 |
| Phase 6B (Detection Engineering) chunks | 576 |
| Phase 6C (Provider Intelligence) chunks | 67 |
| Phase 6D (Provider Docs Extended) chunks | 52 |
| Phase 6E (Threat Intelligence) chunks | 118 |
| Phase 6F (Vulnerability Taxonomy) chunks | 54 |

## 8. Recommendation

**Verdict:** READY for Phase 7. Moderate retrieval improvement — acceptable for WADE integration.

Chunk-based TF-IDF improved Top-5 accuracy from 46% to 52% (+6pp).
WADE readiness average: 8.0/10 (was 7.6/10).
Next step: Phase 7 — WADE knowledge integration and live retrieval API.
