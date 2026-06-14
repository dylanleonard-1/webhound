"""Phase 6F: Write CVE/NVD/CVSS/CISA/OWASP normalized files."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASE = os.path.join(ROOT, "corpus", "normalized", "vulnerability-taxonomy")

DIRS = ["cve", "nvd", "cvss", "cisa-kev", "owasp"]
for d in DIRS:
    os.makedirs(os.path.join(BASE, d), exist_ok=True)

FILES = {
"cve/pd-vt-cve--program.md": """# CVE Program — Authored Reference
source: https://cve.org/About/Overview
live_fetch_status: blocked (JS-heavy SPA)
authority_tier: B (authored synthesis)
ingested: 2026-06-14

## What CVE Is
Common Vulnerabilities and Exposures (CVE) is the industry standard for identifying and
naming publicly known cybersecurity vulnerabilities. Each CVE record provides a unique
identifier (CVE-YYYY-NNNNN), a standardized description of the vulnerability, and
references to additional information.

## CVE ID Structure
Format: CVE-{year}-{sequence}. Examples: CVE-2021-44228 (Log4Shell), CVE-2023-44487 (HTTP/2).
Year = year of assignment (not necessarily year of disclosure or exploitation).
Sequence = unique numeric sequence within that year.

## CVE Records Contain
- CVE ID
- Description (standardized text identifying the vulnerability, affected product/version)
- References (vendor advisories, NVD entry, researcher disclosures)
- CWE mappings (root-cause weakness types from MITRE CWE)
- Published and last-modified dates

## CVE Numbering Authorities (CNAs)
CNAs are organizations authorized to assign CVE IDs. Types include:
- Root CNA: MITRE (assigns CVEs with no CNA scope)
- Vendor CNAs: Microsoft, Google, Apple, Red Hat, etc. (assign CVEs for own products)
- Coordinator CNAs: CERT/CC, national CERTs
CNAs must follow CVE Program rules on disclosure and quality.

## CVE vs CWE vs NVD
- CVE: specific vulnerability in specific product/version
- CWE: weakness type/class (root cause category, not specific to a product)
- NVD: NIST database that enriches CVE records with CVSS scores, CPE, CWE mappings

## When WebHound Assigns CVE References
Only when: (1) scanner identifies a specific product version with a known CVE, or
(2) Nuclei template explicitly maps a finding to a CVE. Do NOT assign CVE IDs to
generic findings like missing headers or misconfiguration classes.
""",

"nvd/pd-vt-nvd--cvss.md": """# NVD CVSS Reference
source: https://nvd.nist.gov/vuln-metrics/cvss
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## What CVSS Is
Common Vulnerability Scoring System (CVSS) provides a qualitative measure of
vulnerability severity. Important: CVSS is NOT a measure of risk. It measures inherent
severity characteristics of the vulnerability itself, independent of context.

## Versions Supported by NVD
- CVSS v2.0 (legacy; NVD stopped generating new v2.0 assessments July 2022)
- CVSS v3.x (current primary for existing CVEs)
- CVSS v4.0 (new; NVD transitioning)

## Severity Ratings (v3.x and v4.0)
- None: 0.0
- Low: 0.1-3.9
- Medium: 4.0-6.9
- High: 7.0-8.9
- Critical: 9.0-10.0

## NVD Scoring Scope
NVD assesses only BASE metrics (inherent vulnerability characteristics).
NVD does NOT assess Temporal, Environmental, or Supplemental metrics.
Users apply those metrics themselves for organizational context.

## NVD vs FIRST
CVSS standard is owned by FIRST.Org. NVD is an implementation/enrichment authority.
NVD scores may differ from vendor-assigned CVSS scores; both are informational.

## Worst-Case Scoring
When vendors withhold details, NVD applies worst-case scenario values.
In extreme cases, scores default to 10.0.

## Attribution Requirement
Applications using NVD data must display:
"This product uses data from the NVD API but is not endorsed or certified by the NVD."
""",

"nvd/pd-vt-nvd--api.md": """# NVD API — Technical Reference
source: https://nvd.nist.gov/developers/start-here
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## API Access
Base URL: https://services.nvd.nist.gov/rest/json/
Format: JSON with ISO-8601 datetime objects
Authentication: API key via request header (optional but strongly recommended)

## Rate Limits
- Without key: 5 requests per 30-second rolling window
- With key: 50 requests per 30-second rolling window
- Recommended: 6-second sleep between requests for stability

## Key Endpoints
- Vulnerabilities API: search CVE records with filtering
- Products API: CPE dictionary and statistics
- Filtering: by CVE ID, keyword, CWE ID, severity, dates

## Pagination
Start with startIndex=0, increment by resultsPerPage until exceeding total.
For updates: use lastModStartDate / lastModEndDate (poll no more frequently than 2 hours).

## Data License
All NIST publications are in the public domain.
Required attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD."

## WebHound Use
Do NOT bulk-import NVD feed — this violates Phase 6F limits (no bulk CVE dumps).
Use NVD API to look up specific CVEs identified by scanner/Nuclei findings.
""",

"cvss/pd-vt-cvss--v31.md": """# CVSS v3.1 Specification Reference
source: https://www.first.org/cvss/v3-1/
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Framework
CVSS v3.1 managed by FIRST.Org CVSS-SIG. Provides standardized vulnerability severity scoring.

## Base Metric Groups

### Exploitability Metrics
- Attack Vector (AV): Network (N) / Adjacent (A) / Local (L) / Physical (P)
  - Network = remotely exploitable; highest impact on score
- Attack Complexity (AC): Low (L) / High (H)
  - Low = no special conditions; High = requires specific prerequisites
- Privileges Required (PR): None (N) / Low (L) / High (H)
- User Interaction (UI): None (N) / Required (R)

### Impact Metrics
- Scope (S): Unchanged (U) / Changed (C) — does impact extend beyond the vulnerable component?
- Confidentiality (C): None (N) / Low (L) / High (H)
- Integrity (I): None (N) / Low (L) / High (H)
- Availability (A): None (N) / Low (L) / High (H)

## Severity Ratings
- None: 0.0 | Low: 0.1-3.9 | Medium: 4.0-6.9 | High: 7.0-8.9 | Critical: 9.0-10.0

## Vector String Format
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical (example)

## Extended Metrics
- Temporal: Exploit Code Maturity, Remediation Level, Report Confidence (time-varying)
- Environmental: Modified base metrics + security requirements for org-specific scoring

## WebHound Usage Policy
Do NOT compute CVSS for generic findings (missing headers, misconfigs) without a CVE.
CVSS is for known CVEs with defined attack paths. Use OWASP Risk Rating for scan findings.
""",

"cvss/pd-vt-cvss--v40.md": """# CVSS v4.0 Reference
source: https://www.first.org/cvss/v4-0/
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Key Changes from v3.1

### Scoring Nomenclature
- CVSS-B: Base metrics only
- CVSS-BT: Base + Threat metrics
- CVSS-BE: Base + Environmental
- CVSS-BTE: Base + Threat + Environmental (most complete)

### New Base Metrics
- Attack Requirements (AT): preconditions needed beyond Attack Complexity
  - None (N): no special prerequisite | Present (P): specific setup required
- User Interaction (UI) values expanded to Passive (P) and Active (A)

### Scope Removed; Replaced by System Impact
- Vulnerable System: VC (Confidentiality), VI (Integrity), VA (Availability)
- Subsequent System: SC, SI, SA — explicitly models cascading effects

### Threat Metric Group (replaces Temporal)
- Exploit Maturity (E): replaces Exploit Code Maturity
- Remediation Level (RL) and Report Confidence (RC) removed

### New Supplemental Metrics (informational only; do not change score)
- Safety (S), Automatable (A), Recovery (R), Value Density (V),
  Vulnerability Response Effort (RE), Provider Urgency (U)

## OT/ICS Emphasis
Safety metrics MSI:S and MSA:S address critical infrastructure safety impacts.

## WebHound Relevance
CVSS v4.0 applies to CVEs published after its adoption. NVD transitioning to v4.0.
Same policy as v3.1: do NOT compute CVSS for non-CVE findings.
""",

"cisa-kev/pd-vt-cisa-kev--catalog.md": """# CISA KEV Catalog — Authored Reference
source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
live_fetch_status: blocked (HTTP 403)
authority_tier: B (authored synthesis)
ingested: 2026-06-14

## What KEV Is
The CISA Known Exploited Vulnerabilities (KEV) catalog is a list of CVEs that have
confirmed evidence of active exploitation in the wild. Published and maintained by CISA.

## KEV Entry Fields
- CVE ID: the specific CVE being tracked
- Vendor/Project: affected software vendor or project
- Product: specific product name
- Vulnerability Name: descriptive name (e.g., "Apache Log4j2 Remote Code Execution")
- Date Added: when CISA confirmed active exploitation
- Short Description: brief technical description
- Required Action: what federal agencies must do (e.g., "Apply updates per vendor instructions")
- Due Date: deadline for FCEB agency compliance

## Who Must Comply
Binding Operational Directive (BOD) 22-01 mandates all Federal Civilian Executive Branch
(FCEB) agencies remediate KEV items by the due date. Private sector is strongly encouraged
but not legally mandated to follow KEV guidance.

## Why KEV Matters for Prioritization
A CVE in KEV = confirmed real-world exploitation. KEV status elevates remediation priority
above raw CVSS score. A Medium CVSS CVE with KEV status is more urgent than a High CVSS
CVE with no exploitation evidence.

## Update Cadence
Updated on a rolling basis as CISA confirms new exploitation evidence. No fixed schedule.

## WebHound Relevance
If scanner/Nuclei identifies a specific vulnerable product with a CVE on the KEV list,
this is a critical escalation signal for the customer report. "Actively exploited per
CISA KEV" should appear in the finding. DO NOT bulk-commit the KEV JSON feed to the repo.
""",

"owasp/pd-vt-owasp--risk-rating.md": """# OWASP Risk Rating Methodology — Reference
source: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Core Formula
Risk = Likelihood x Impact

## Likelihood Factors (0-9 each; average = overall likelihood)

### Threat Agent Factors
- Skill level: 1 (no skills) to 9 (security penetration expert)
- Motive: 1 (low reward) to 9 (high reward)
- Opportunity: 0 (full access required) to 9 (no access required)
- Size: 2 (developers) to 9 (anonymous internet users)

### Vulnerability Factors
- Ease of discovery: 1 (practically impossible) to 9 (automated tools)
- Ease of exploit: 1 (theoretical) to 9 (automated tools)
- Awareness: 1 (unknown) to 9 (public knowledge)
- Intrusion detection: 1 (active detection) to 9 (not logged)

Likelihood categories: LOW (0-<3), MEDIUM (3-<6), HIGH (6-9)

## Impact Factors (0-9 each)

### Technical Impact
- Confidentiality loss, Integrity loss, Availability loss, Accountability loss

### Business Impact
- Financial damage, Reputation damage, Non-compliance, Privacy violation

## Risk Severity (3x3 matrix: Likelihood x Impact)
Results in: Critical, High, Medium, or Low risk rating.
Business impact overrides technical impact when available.

## vs CVSS
OWASP Risk Rating: context-dependent, customizable, designed for application assessment.
CVSS: standardized, universal, designed for CVE scoring. Use OWASP for scan findings.

## WebHound Use
Apply OWASP Risk Rating methodology to scanner findings that have no CVE.
Adjust threat agent factors for WebHound's attacker model (internet-accessible public sites).
""",

"owasp/pd-vt-owasp--top10.md": """# OWASP Top 10 2021 — Reference
source: https://owasp.org/Top10/2021/ (A01 live-fetched; remainder authored from public knowledge)
live_fetch_status: partial (A01 live; A02-A10 authored)
authority_tier: A (live A01); B (authored A02-A10)
ingested: 2026-06-14

## A01:2021 — Broken Access Control (live-fetched)
Failure to enforce user permissions. Includes: privilege escalation, insecure direct object
references, CORS misconfigurations, CSRF, path traversal to restricted files.
Key CWEs: CWE-200, CWE-201, CWE-352, CWE-862, CWE-863.

## A02:2021 — Cryptographic Failures
Failures related to cryptography exposing sensitive data. Includes: weak ciphers, missing TLS,
cleartext data at rest/transit, insufficient key management.
Key CWEs: CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-326, CWE-327.

## A03:2021 — Injection
SQL, NoSQL, OS, LDAP injection; XSS. User-supplied data not validated/escaped.
Key CWEs: CWE-79 (XSS), CWE-89 (SQLi), CWE-73 (path injection).

## A04:2021 — Insecure Design
Missing or ineffective security controls at design phase. Threat modeling failures.
Key CWEs: CWE-209, CWE-256, CWE-501, CWE-522.

## A05:2021 — Security Misconfiguration
Insecure defaults, unnecessary features enabled, verbose errors, missing security headers.
Key CWEs: CWE-16, CWE-611 (XXE). Includes: missing CSP, missing HSTS, missing cookie flags.

## A06:2021 — Vulnerable and Outdated Components
Using components with known vulnerabilities; unpatched software. Where CVE/NVD are most relevant.
Key CWEs: CWE-1104.

## A07:2021 — Identification and Authentication Failures
Broken authentication: weak credentials, session mismanagement, missing MFA.
Key CWEs: CWE-255, CWE-259, CWE-287, CWE-288, CWE-290.

## A08:2021 — Software and Data Integrity Failures
Missing integrity checks: insecure deserialization, missing SRI, untrusted CI/CD pipelines.
Key CWEs: CWE-494, CWE-502, CWE-829.

## A09:2021 — Security Logging and Monitoring Failures
Insufficient logging to detect and respond to breaches. Hard to directly scan for passively.

## A10:2021 — Server-Side Request Forgery (SSRF)
CWE-918. Server fetches user-supplied URLs without validation; enables internal network access.
Earned dedicated Top 10 category (previously part of injection) reflecting growing prevalence.
""",
}

for rel_path, content in FILES.items():
    abs_path = os.path.join(BASE, rel_path.replace("/", os.sep))
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  wrote: corpus/normalized/vulnerability-taxonomy/{rel_path}")

print(f"Done: {len(FILES)} other normalized files")
