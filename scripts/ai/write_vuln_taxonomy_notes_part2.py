"""Phase 6F: Write vulnerability taxonomy synthesis knowledge notes (part 2)."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KT = os.path.join(ROOT, "knowledge", "vulnerability-taxonomy")

NOTES = {}

NOTES["vulnerability-taxonomy-overview.md"] = """# Vulnerability Taxonomy Overview
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## The Four Systems
- CVE: assigns unique IDs to specific, publicly known vulnerabilities in specific products
- CWE: classifies weakness TYPES (root causes); one CWE can underlie thousands of CVEs
- NVD: NIST database enriching CVE records with CVSS scores, CPE product data, CWE mappings
- CVSS: scoring framework for severity of a specific vulnerability (not a risk metric)

## How They Relate
CWE (weakness class) -> CVE (specific occurrence) -> NVD (enriched record with CVSS score)
CISA KEV: subset of CVEs confirmed actively exploited (highest remediation priority)
OWASP Top 10: high-level risk categories for web applications (not tied to specific CVEs)

## What WebHound Uses Each For
- CWE: classify scanner finding categories (e.g., missing header -> CWE-1021)
- CVE: reference only when scanner/Nuclei identifies a specific vulnerable product version
- CVSS: reference only for CVE-tied findings; do NOT compute CVSS for generic misconfigs
- KEV: escalation signal when a confirmed CVE is actively exploited
- OWASP Top 10: high-level context for customer reports
- OWASP Risk Rating: internal methodology for non-CVE scanner finding severity
"""

NOTES["cve-vs-cwe-vs-nvd.md"] = """# CVE vs CWE vs NVD — Distinctions
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## CVE (Common Vulnerabilities and Exposures)
- What: a specific exploitable vulnerability in a specific product/version
- Who assigns: CVE Numbering Authorities (CNAs) including MITRE, vendors, national CERTs
- Format: CVE-YYYY-NNNNN
- Contains: description, affected version, references, CWE mapping
- Example: CVE-2021-44228 = Log4j 2.x JNDI injection (specific product, specific version)

## CWE (Common Weakness Enumeration)
- What: a weakness TYPE or root-cause category; not tied to specific products
- Who assigns: MITRE (community-developed)
- Format: CWE-NNN
- Contains: weakness name, description, consequences, mitigations
- Example: CWE-79 = any XSS weakness anywhere (class, not a specific CVE)

## NVD (National Vulnerability Database)
- What: NIST's enriched database of CVE records
- Who operates: NIST (U.S. National Institute of Standards and Technology)
- Adds to CVEs: CVSS base scores, CPE (affected product) data, CWE mappings
- Does NOT: create CVEs or own the CVSS standard
- Attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD."

## Key Distinctions for WebHound
- Missing CSP header: CWE-1021/CWE-693 (weakness class) — NOT a CVE
- Log4j detected in response: CVE-2021-44228 (specific CVE) — reference NVD for CVSS
- SQL error visible in response: CWE-89 context — NOT a CVE unless specific app version matched
- WordPress xmlrpc.php exposed: may match specific CVE if version confirmed
"""

NOTES["cvss-severity-model.md"] = """# CVSS Severity Model
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Score Ranges and Labels (v3.1 and v4.0)
- None: 0.0
- Low: 0.1-3.9
- Medium: 4.0-6.9
- High: 7.0-8.9
- Critical: 9.0-10.0

## What CVSS Measures (Base Metrics v3.1)
Exploitability:
- Attack Vector: Network(highest) > Adjacent > Local > Physical(lowest)
- Attack Complexity: Low(worse) vs High(better)
- Privileges Required: None(worse) > Low > High(better)
- User Interaction: None(worse) vs Required(better)
- Scope: Changed(worse) vs Unchanged

Impact:
- Confidentiality, Integrity, Availability: each None / Low / High

## What CVSS Does NOT Measure
- Probability of exploitation (risk)
- Whether the vulnerability is actually exploited in the wild (that's KEV)
- Organization-specific impact (that requires Environmental metrics)
- Ease of detection
- Business impact (that's OWASP Risk Rating)

## Common Misuse
Do NOT use CVSS scores for findings without a CVE (missing headers, misconfigs).
CVSS 10.0 does not mean "you will be hacked today" — it means the vulnerability is
maximally severe IF exploited. Combine with KEV status for actual prioritization.
"""

NOTES["cvss-v31-vs-v40.md"] = """# CVSS v3.1 vs v4.0 Comparison
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## v3.1 (Current widely-used version)
Base metrics: AV, AC, PR, UI, Scope, C, I, A
Temporal: Exploit Code Maturity, Remediation Level, Report Confidence
Environmental: Modified base metrics + security requirements
Vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## v4.0 (New; NVD transitioning)
New base metrics: Attack Requirements (AT), expanded User Interaction (Passive/Active)
Replaces Scope with: Vulnerable System (VC/VI/VA) + Subsequent System (SC/SI/SA)
Temporal renamed Threat; RL/RC removed; Exploit Maturity improved
New Supplemental metrics (informational only): Safety, Automatable, Recovery, etc.
Vector string: CVSS:4.0/...

## Key Behavioral Differences
- v4.0 better models cascading/lateral impact via Subsequent System metrics
- v4.0 supplemental metrics improve OT/ICS and safety-critical system assessment
- v4.0 scores not directly comparable to v3.1 scores for same CVE

## WebHound Impact
NVD will publish v4.0 scores for new CVEs. Both v3.1 and v4.0 scores may coexist.
When displaying CVSS to customers, specify version: "CVSS v3.1: 9.8 Critical" not just "9.8".
"""

NOTES["exploitability-vs-impact.md"] = """# Exploitability vs Impact
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Definitions
- Exploitability: how easy is it to attack (Attack Vector, Complexity, Privileges, User Interaction)
- Impact: what damage results (Confidentiality, Integrity, Availability loss)
- Severity = function of both; neither alone determines score

## High-Exploitability Examples
- Network-accessible, no auth, no user interaction: AV:N/AC:L/PR:N/UI:N
- These start with a high exploitability sub-score
- But if impact is low (e.g., no C/I/A effect) -> overall score stays moderate

## High-Impact Examples
- Full credential exposure + system takeover: C:H/I:H/A:H
- But if only exploitable locally with admin access: PR:H/AV:L -> score reduced

## WebHound Implications
- Missing security header (CSP, X-Frame-Options): HIGH exploitability potential but
  LOW intrinsic impact (requires secondary exploitation step) -> Medium-Low finding
- Exposed .env with database credentials: LOW exploitability threshold (just HTTP GET)
  but HIGH impact (full data access) -> High finding

## Confidence vs Severity
Severity = how bad IF exploited. Confidence = how certain we are it's exploitable.
A High CVSS CVE with no exploitation evidence has different operational priority
than a Medium CVSS CVE confirmed in CISA KEV.
"""

NOTES["severity-vs-confidence.md"] = """# Severity vs Confidence in WebHound
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Two Separate Dimensions
SEVERITY: how bad would it be if this finding represents a real vulnerability?
CONFIDENCE: how certain are we that this finding is a true positive?

## Why They Must Be Tracked Separately
A High-severity finding with Low confidence = do not report as confirmed High-risk.
A Low-severity finding with High confidence = report clearly but appropriately scoped.

## WADE Tracking
WADE tracks confidence score (0-100) separately from severity rating.
Do NOT merge confidence into severity ("we think this might be critical" = misleading).

## Confidence Factors for WebHound Findings
- Passive header check (no response variation): High confidence (header is absent or present)
- Active file fetch (HTTP 200 + content match): High confidence
- Nuclei template with verified indicator: High confidence + CVE reference if present
- Heuristic pattern match (suspicious obfuscation): Low-Medium confidence
- TI match on shared infrastructure: Low-Medium confidence

## Severity Calibration
- Confirmed .env exposure with live credentials: High severity + High confidence = Critical report
- Missing HSTS on non-sensitive marketing page: Low-Medium severity, High confidence = Informational
- Suspicious third-party script domain: Medium severity, Low confidence = "flag for review"

## Customer-Safe Application
Always state confidence in customer reports:
CONFIRMED: "We identified..." | SUSPECTED: "Evidence suggests..." | MONITORING: "We observed..."
"""

NOTES["cisa-kev-known-exploited-model.md"] = """# CISA KEV Known Exploited Vulnerabilities Model
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## What KEV Tells Us
KEV = "this CVE is being actively exploited in the wild — confirmed by CISA."
KEV status is a prioritization signal ABOVE CVSS score.
A Medium CVSS CVE on KEV requires faster remediation than a Critical CVSS CVE not on KEV.

## KEV vs CVSS Priority Matrix
Critical CVSS + KEV: patch immediately (P0)
Critical CVSS + no KEV: patch urgently (P1)
High CVSS + KEV: patch urgently (P1)
Medium CVSS + KEV: patch in normal cycle but expedited
Low CVSS + KEV: unusual; evaluate context

## FCEB Mandate vs Commercial Context
Federal agencies: must remediate KEV items by due date (BOD 22-01).
Commercial customers: KEV is a strong recommendation, not legally binding.
WebHound should frame KEV for commercial customers as: "CISA has confirmed this
vulnerability is actively exploited; we recommend treating it as highest priority."

## How WebHound Uses KEV
1. If Nuclei/scanner identifies a specific CVE -> check if CVE is on KEV
2. If KEV: escalate finding priority; add "Actively exploited per CISA KEV" language
3. Do NOT commit the KEV JSON feed to the repository
4. Reference KEV website in customer report; do not reproduce the full catalog

## Important Limitation
KEV only covers vulnerabilities with a specific CVE. Generic misconfigurations (missing
headers, weak TLS) do not appear in KEV regardless of severity.
"""

NOTES["owasp-risk-rating-model.md"] = """# OWASP Risk Rating Model for WebHound
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Why OWASP Risk Rating for Non-CVE Findings
CVSS is designed for CVEs with known attack paths. Most WebHound scanner findings
(missing headers, exposed files, cookie flags) have no CVE. OWASP Risk Rating provides
a structured methodology for rating these: Risk = Likelihood x Impact.

## WebHound Attacker Model (Threat Agent Factors)
Default attacker for internet-accessible sites:
- Skill: 6 (skilled attacker with web exploitation knowledge)
- Motive: 6 (financial gain, competitive intelligence)
- Opportunity: 7 (internet-accessible with automated tools)
- Size: 9 (anonymous internet users, automated bots)
Avg threat agent score: ~7 (HIGH)

## Likelihood Adjustments
Apply vulnerability factors to adjust from the base threat-agent score:
- Easy of discovery of MISSING HEADER: 9 (automated scanners find instantly)
- Ease of exploit: depends on finding type
  - Missing CSP: 7 (many XSS vectors available if XSS exists)
  - Exposed .env: 9 (trivial HTTP GET)
  - Missing HSTS: 5 (requires network position for downgrade)

## Impact Assessment
Technical: confidentiality, integrity, availability loss
Business: financial, reputation, compliance, privacy

## Risk Mapping to WebHound Severity Labels
OWASP Critical/High -> WebHound High/Critical
OWASP Medium -> WebHound Medium
OWASP Low -> WebHound Low/Informational
"""

NOTES["owasp-top-10-mapping.md"] = """# OWASP Top 10 2021 — WebHound Mapping
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

| OWASP Category | WebHound Finding Types |
|---|---|
| A01 Broken Access Control | Exposed admin paths, CORS misconfiguration, open redirects |
| A02 Cryptographic Failures | Mixed content, TLS issues, cookies without Secure, exposed credentials |
| A03 Injection | XSS indicators, SQLi indicators, command injection (active tests) |
| A04 Insecure Design | Missing threat modeling (cannot scan directly) |
| A05 Security Misconfiguration | Missing CSP/HSTS/X-Frame-Options/X-Content-Type-Options, exposed .git/.env |
| A06 Vulnerable Components | Nuclei CVE findings, WordPress/plugin version detection |
| A07 Auth Failures | Exposed login pages, missing MFA indicators, insecure session cookies |
| A08 Software Integrity Failures | Missing SRI on third-party scripts |
| A09 Logging Failures | Cannot scan directly; out of scope for passive scanner |
| A10 SSRF | Open redirect indicators, webhook endpoints (requires active validation) |

## Most Common WebHound-to-OWASP Mappings
- Missing security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy): A05
- Cookie flags (Secure/HttpOnly/SameSite): A02 + A05
- Exposed sensitive files: A05 + A02
- Third-party script TI match: A06 (if CVE) or A05 (if misconfiguration)
- Nuclei CVE finding: A06 (primary)
- TLS expiry/misconfiguration: A02
"""

NOTES["webhound-finding-taxonomy.md"] = """# WebHound Finding Taxonomy
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14
Maps scanner finding categories to CWE, OWASP Top 10, and severity guidance.

## Header Findings
| Finding | CWE | OWASP | Severity | Notes |
|---|---|---|---|---|
| Missing Content-Security-Policy | CWE-693/1021 | A05 | Low-Medium | Context: XSS prerequisite |
| Missing HSTS | CWE-319 | A02 | Medium | Higher on auth/payment pages |
| Missing X-Frame-Options | CWE-1021 | A05 | Low-Medium | Prefer CSP frame-ancestors |
| Missing X-Content-Type-Options | CWE-16 | A05 | Low | MIME sniffing risk |
| Missing Referrer-Policy | CWE-200 | A02 | Low | Information leakage |

## Cookie Findings
| Finding | CWE | OWASP | Severity |
|---|---|---|---|
| Cookie without Secure flag | CWE-614 | A05/A02 | Low-Medium |
| Cookie without HttpOnly | CWE-1004 | A05 | Low-Medium |
| Cookie SameSite=None without Secure | CWE-614 | A05 | Medium |

## Sensitive File Exposure
| Finding | CWE | OWASP | Severity |
|---|---|---|---|
| Exposed .env file | CWE-200/CWE-798 | A05/A02 | High-Critical |
| Exposed .git directory | CWE-200 | A05 | High |
| Exposed backup file | CWE-200 | A05 | Medium-High |
| Exposed admin path (no auth) | CWE-306 | A01/A07 | High |

## Third-Party / Script Findings
| Finding | CWE | OWASP | Severity |
|---|---|---|---|
| Third-party script TI match | CWE-829 | A06/A08 | High (if confirmed) |
| Suspicious JS obfuscation | CWE-116 | A03 | Low-Medium (confidence-limited) |
| Missing SRI on external script | CWE-494 | A08 | Low-Medium |
| Malicious redirect indicator | CWE-601 | A01 | High |

## Active / External Validation Findings
| Finding | CWE | OWASP | Severity |
|---|---|---|---|
| Nuclei CVE match | See specific CVE CWE | A06 | Per CVE CVSS |
| ZAP passive finding | Varies | Varies | Per ZAP confidence |
| TLS expiry | CWE-295 | A02 | Medium-High |
| TLS misconfiguration | CWE-327 | A02 | Medium-High |

## Infrastructure Findings
| Finding | CWE | OWASP | Severity |
|---|---|---|---|
| GraphQL exposure | CWE-200 | A05 | Medium |
| Swagger/OpenAPI exposure | CWE-200 | A05 | Low-Medium |
| WordPress xmlrpc/admin exposure | CWE-306 | A07/A05 | Medium |
| Provider-blocked scan | N/A | N/A | Informational |
| DNS misconfiguration | CWE-350 | A05 | Medium |
"""

NOTES["webhound-cwe-mapping.md"] = """# WebHound CWE Mapping Reference
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Direct CWE Mappings for Common Scanner Findings

Missing CSP: CWE-693 (Protection Mechanism Failure) / CWE-1021 (re: clickjacking)
Missing HSTS: CWE-319 (Cleartext Transmission of Sensitive Information)
Missing X-Frame-Options/frame-ancestors: CWE-1021 (Clickjacking)
Missing X-Content-Type-Options: CWE-16 (Configuration)
Missing Referrer-Policy: CWE-200 (Information Exposure)
Cookie without Secure: CWE-614
Cookie without HttpOnly: CWE-1004
SameSite=None missing Secure: CWE-614 (extension)
Mixed content: CWE-319
Exposed .env: CWE-200 + CWE-312 (Cleartext Storage) + CWE-798 (if credentials)
Exposed .git: CWE-200 (Source Code Disclosure)
Exposed backup: CWE-200
Exposed admin (no auth): CWE-306 (Missing Authentication for Critical Function)
Open redirect: CWE-601 (URL Redirection to Untrusted Site)
Missing SRI: CWE-494 (Download of Code Without Integrity Check)
Suspicious script obfuscation: CWE-116 (Improper Encoding) — low confidence
GraphQL/Swagger exposure: CWE-200 (Exposure of Sensitive Information)
XSS indicator: CWE-79
SQLi indicator: CWE-89
SSRF indicator: CWE-918
Command injection: CWE-78
XXE: CWE-611
TLS misconfiguration: CWE-326/CWE-327 (Inadequate/Use of Broken Algorithm)
Hardcoded credential in JS: CWE-798

## Usage Rules
1. Assign CWE ONLY when the weakness type is confirmed or highly probable
2. Do NOT assign both a parent (CWE-693) AND a child (CWE-1021) for same finding
3. For multi-cause findings, use the most specific applicable CWE
4. CVE assignment is SEPARATE from CWE assignment
"""

NOTES["webhound-cvss-usage-policy.md"] = """# WebHound CVSS Usage Policy
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## When to Use CVSS
ONLY for findings tied to a specific CVE with a published NVD CVSS score.
Source: NVD record for the CVE. Always cite the version: "CVSS v3.1: 9.8 Critical."

## When NOT to Use CVSS
- Missing security headers (no CVE; use OWASP Risk Rating)
- Misconfiguration findings (no specific product CVE)
- Cookie flag issues (no CVE; use CWE + OWASP)
- Exposed sensitive files (no CVE; use CWE + business impact)
- Third-party TI matches without a product CVE

## Do NOT Compute Custom CVSS
Do not manually calculate a CVSS vector string for a non-CVE finding to make it look
like a CVE-based finding. This misleads customers about the nature of the finding.

## Vendor vs NVD Scores
Vendors often publish their own CVSS scores that differ from NVD's score.
When citing CVSS, note: "NVD CVSS v3.1: X.X [Severity]" to be unambiguous.

## Attribution
Customer reports using CVSS/NVD data should include:
"Severity scores from the NVD API (nist.gov/nvd). NVD does not endorse WebHound."

## CISA KEV Escalation
If CVE is in CISA KEV, add: "This vulnerability is actively exploited per CISA KEV;
immediate remediation is recommended regardless of CVSS score."
"""

NOTES["when-not-to-assign-cve.md"] = """# When NOT to Assign a CVE
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## CVE Requires a Specific Vulnerable Product
CVE-YYYY-NNNNN means: "software product X version Y has vulnerability Z."
A CVE cannot be assigned to a missing header, a misconfiguration, or a general
web security weakness unless it is tied to a known-vulnerable application version.

## Common NON-CVE Findings
These are weaknesses/misconfigs, not CVEs:
- Missing Content-Security-Policy: configuration weakness, not a CVE
- Missing HSTS: configuration weakness, not a CVE
- Cookie without Secure/HttpOnly flags: configuration weakness
- Exposed .env or .git: configuration/deployment error
- Open redirect: weakness (CWE-601) unless specific app version CVE exists
- Missing SRI on scripts: configuration weakness

## When CVE Assignment IS Appropriate
- Nuclei template fires for a known-CVE payload AND version is confirmed
- Scanner detects a specific software version (e.g., WordPress 5.8.1 with known plugin CVE)
- ZAP finding maps to a documented CVE in a framework or library
- Third-party component identified with a version-specific CVE match

## Missing Headers Are NOT Auto-High CVSS
Even if missing CSP sounds dangerous, it has no CVSS score because there is no CVE.
The severity is context-dependent (what else is present on the page, what's the threat model).
Use OWASP Risk Rating for non-CVE findings.

## The Common Mistake
"The site is missing HSTS — CVSS 7.5 High" -> WRONG. HSTS absence is a hardening gap.
Correct: "Missing HSTS (CWE-319): Medium finding per OWASP Risk Rating; increases risk
if attacker has network access and can perform SSL stripping attacks."
"""

NOTES["customer-safe-vulnerability-language.md"] = """# Customer-Safe Vulnerability Language
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## Principles
1. Describe WHAT was found, not WHAT could hypothetically happen in a worst case
2. Match certainty language to evidence quality (Confirmed vs Possible vs Monitoring)
3. Do not cite CVSS scores for non-CVE findings
4. Avoid unfounded exploitability claims
5. Provide actionable remediation steps

## Severity Labels
Critical (CVE+KEV or confirmed creds): "We identified [finding]. Actively exploited; remediate immediately."
High (confirmed dangerous exposure): "[Finding] at [location]. Exposes [data]; remediate as priority."
Medium (exploitation requires conditions): "[Finding]. Under certain conditions, may allow [impact]. Recommend [remediation]."
Low/Informational: "[Finding] is a best-practice header not currently enabled. Reduces risk from [attack]."

## Prohibited Language
- "Your site is critically vulnerable and will be hacked" (unsupported)
- "CVSS 9.8 Critical" for a missing header (no CVE)
- "Attackers are currently targeting your site" (unsupported without TI confirmation)

## When TI Match Is Present
"A resource on your site matches threat intelligence indicators for [threat type].
This may indicate [impact]. Immediate investigation recommended."
Do not claim confirmed compromise without corroborating evidence.
"""

NOTES["wade-taxonomy-relevance.md"] = """# Vulnerability Taxonomy — WADE Relevance
Category: synthesis | WebHound Phase 6F | Updated: 2026-06-14

## How WADE Uses Taxonomy
CWE: assigns CWE IDs to scanner findings for pattern analysis; confidence >=0.7 required.
CVE: records only when Nuclei/scanner provides one; tracks CVE->KEV escalation.
CVSS: stores NVD scores for CVE-linked findings only; never computes custom CVSS.
OWASP Risk Rating: used internally for non-CVE finding severity.
CISA KEV: checks each confirmed CVE; adds priority_escalation:cisa_kev flag.
KEV language: "Actively exploited per CISA KEV as of [date]."

## WADE MUST NOT Rules (Taxonomy-Specific)
- MUST NOT assign CVE ID to a missing-header or misconfiguration finding
- MUST NOT display CVSS scores for non-CVE findings in customer reports
- MUST NOT claim Critical severity based on CWE class alone
- MUST NOT report "vulnerability" when the finding is a hardening gap

## WADE SHOULD Rules
- SHOULD assign CWE to every finding with >=0.7 confidence
- SHOULD include OWASP Top 10 category in customer report context
- SHOULD note KEV status when a CVE is confirmed
- SHOULD track confidence and severity as independent dimensions
"""

for rel_path, content in NOTES.items():
    abs_path = os.path.join(KT, rel_path.replace("/", os.sep))
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Done: {len(NOTES)} synthesis knowledge notes (part 2)")
