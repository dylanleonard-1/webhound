"""Phase 6F: Write vulnerability taxonomy READMEs and CWE knowledge notes."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KT = os.path.join(ROOT, "knowledge", "vulnerability-taxonomy")

DIRS = ["", "cwe", "cve", "nvd", "cvss", "cisa-kev", "owasp-risk", "owasp-top-10"]
for d in DIRS:
    os.makedirs(os.path.join(KT, d) if d else KT, exist_ok=True)

NOTES = {}

NOTES["README.md"] = """# Vulnerability Taxonomy Knowledge
Phase 6F | WebHound AI Knowledge Layer | Updated: 2026-06-14

Covers CVE/CWE/NVD/CVSS/CISA KEV/OWASP as applied to WebHound scanner findings.
NO live vulnerability feeds; NO bulk CVE/NVD dumps; documentation/modeling only.

## Source Directories
- cwe/ — CWE weakness definitions (15 WebHound-relevant CWEs)
- cve/ — CVE program overview
- nvd/ — NVD role and API
- cvss/ — CVSS scoring model (v3.1 and v4.0)
- cisa-kev/ — CISA Known Exploited Vulnerabilities overview
- owasp-risk/ — OWASP Risk Rating Methodology
- owasp-top-10/ — OWASP Top 10 2021 mapping

## Synthesis Notes
- vulnerability-taxonomy-overview.md
- cve-vs-cwe-vs-nvd.md
- cvss-severity-model.md
- cvss-v31-vs-v40.md
- exploitability-vs-impact.md
- severity-vs-confidence.md
- cisa-kev-known-exploited-model.md
- owasp-risk-rating-model.md
- owasp-top-10-mapping.md
- webhound-finding-taxonomy.md
- webhound-cwe-mapping.md
- webhound-cvss-usage-policy.md
- customer-safe-vulnerability-language.md
- wade-taxonomy-relevance.md
- when-not-to-assign-cve.md
"""

NOTES["cwe/README.md"] = "# CWE Knowledge Notes\n15 WebHound-relevant Common Weakness Enumeration definitions.\n"
NOTES["cve/README.md"] = "# CVE Program Knowledge\nCVE ID assignment, CNA structure, CVE record fields.\n"
NOTES["nvd/README.md"] = "# NVD Knowledge\nNVD role, CVSS enrichment, API access.\n"
NOTES["cvss/README.md"] = "# CVSS Knowledge\nCVSS v3.1 and v4.0 scoring models.\n"
NOTES["cisa-kev/README.md"] = "# CISA KEV Knowledge\nKnown Exploited Vulnerabilities catalog model.\n"
NOTES["owasp-risk/README.md"] = "# OWASP Risk Rating Knowledge\nLikelihood x Impact methodology.\n"
NOTES["owasp-top-10/README.md"] = "# OWASP Top 10 Knowledge\nOWASP Top 10 2021 categories and WebHound mapping.\n"

NOTES["cwe/cwe-79-xss.md"] = """# CWE-79: Cross-Site Scripting (XSS) — WebHound Note
CWE: 79 | OWASP: A03:2021 Injection | Severity class: Medium-High (context-dependent)

## Description
XSS allows attackers to inject scripts into web pages viewed by other users.
Three types: Reflected (URL-based), Stored (persisted), DOM-based (client-side).

## WebHound Context
- Not a direct passive scanner finding; requires active/manual testing or evidence
- Relevant when: suspicious JS obfuscation detected, third-party scripts inject content
- Malicious third-party script finding may indicate stored XSS delivery vector

## Customer-Safe Language
"Scripts loaded on this page may execute arbitrary JavaScript in visitor browsers,
potentially exposing session credentials or enabling page manipulation."

## Not a CVE Unless
A specific version of a specific web application (e.g., WordPress plugin X v1.2) has
a published CVE for an XSS vulnerability and it is confirmed present.
"""

NOTES["cwe/cwe-89-sql-injection.md"] = """# CWE-89: SQL Injection — WebHound Note
CWE: 89 | OWASP: A03:2021 Injection | Severity class: High-Critical

## Description
Unsanitized user input interpreted as SQL code, enabling data theft, auth bypass,
data modification, or in some cases OS command execution.

## WebHound Context
- Passive scanner has limited SQLi detection (mostly signatures, no exploitation)
- Nuclei/ZAP active templates may detect SQLi indicators via error message analysis
- If Nuclei template fires, reference the specific template finding, not generic CWE-89

## Customer-Safe Language
"The application may not properly validate input before including it in database queries,
potentially allowing unauthorized access to or modification of data."

## Not a CVE Unless
Specific product version with published CVE is confirmed. Custom applications with SQLi
are NOT CVE-eligible; report as CWE-89 weakness finding.
"""

NOTES["cwe/cwe-352-csrf.md"] = """# CWE-352: Cross-Site Request Forgery (CSRF) — WebHound Note
CWE: 352 | OWASP: A01:2021 (access control) | Severity class: Medium

## Description
Missing CSRF protection allows attackers to trick authenticated users into performing
unwanted actions on sites where they are authenticated.

## WebHound Context
- Scanner checks for SameSite cookie attributes (related but not identical to CSRF tokens)
- SameSite=None without Secure = increased CSRF exposure
- Missing CSRF tokens are not directly detectable by passive scanner on form pages

## Customer-Safe Language
"Forms on this site may not implement protections against cross-site request forgery,
potentially allowing malicious sites to trigger actions on behalf of your users."

## Finding Trigger
SameSite cookie issue -> note CSRF relevance as context; do not overstate to "CSRF vulnerability confirmed."
"""

NOTES["cwe/cwe-22-path-traversal.md"] = """# CWE-22: Path Traversal — WebHound Note
CWE: 22 | OWASP: A01:2021 (access control) | Severity class: High

## Description
Improper pathname validation lets attackers access files outside intended directories
using ../ or absolute path sequences.

## WebHound Context
- Exposed sensitive file findings (.env, .git, backup files) are path traversal RESULTS
  but may be caused by server misconfiguration (incorrect directory exposure) not CWE-22
- CWE-22 applies when there is an active traversal mechanism (user-supplied path parameter)
- Passive file exposure via misconfigured web server -> report as exposure finding,
  acknowledge CWE-22 relevance only if traversal vector is confirmed

## Customer-Safe Language
"Sensitive files may be accessible at URLs that should be restricted,
potentially exposing configuration data, credentials, or source code."
"""

NOTES["cwe/cwe-78-command-injection.md"] = """# CWE-78: OS Command Injection — WebHound Note
CWE: 78 | OWASP: A03:2021 Injection | Severity class: Critical

## Description
Server constructs OS commands using user input without proper sanitization.
Attackers modify command structure, potentially executing arbitrary system commands.

## WebHound Context
- Not a passive scanner finding; requires active testing
- If Nuclei template fires for command injection (via timing or output analysis), very high confidence
- Typically affects custom application logic (CGI scripts, admin interfaces, upload handlers)

## Customer-Safe Language
"A server-side component may process user input in a way that could allow execution of
arbitrary system commands, potentially compromising the entire server."

## Severity Note
Critical when confirmed. Do not claim command injection from passive scan alone.
"""

NOTES["cwe/cwe-918-ssrf.md"] = """# CWE-918: Server-Side Request Forgery (SSRF) — WebHound Note
CWE: 918 | OWASP: A10:2021 | Severity class: High-Critical (context-dependent)

## Description
Server fetches user-supplied URLs without validation, enabling attackers to access
internal services, cloud metadata endpoints, or internal network resources.

## WebHound Context
- SSRF indicators: open redirect where destination can be internal IP, webhook endpoints
- Cloud metadata: access to 169.254.169.254 (AWS/GCP) via SSRF = Critical
- Passive scanner can identify open redirect candidates; SSRF requires further validation

## Customer-Safe Language
"The application may make server-side requests to user-supplied URLs without sufficient
validation, potentially exposing internal network resources or cloud infrastructure credentials."

## KEV Note
Several high-profile SSRF CVEs appear on CISA KEV (Log4Shell had SSRF component).
If specific CVE confirmed, check KEV status for escalation.
"""

NOTES["cwe/cwe-200-sensitive-information-exposure.md"] = """# CWE-200: Sensitive Information Exposure — WebHound Note
CWE: 200 (class-level) | OWASP: A02:2021 Cryptographic Failures / A05:2021 Misconfiguration
Severity class: Medium-High (depends on what is exposed)

## Description
Sensitive information reaches unauthorized actors. Class-level; use more specific CWEs
when possible (CWE-209 for error messages, CWE-312 for cleartext storage, etc.).

## WebHound Context
DIRECT scanner findings that map here:
- Exposed .env files: CWE-200 + CWE-312/CWE-615 (credentials in .env)
- Exposed .git directory: CWE-200 (source code exposure)
- Exposed backup files: CWE-200 (application logic/credential exposure)
- Verbose error messages with stack traces: CWE-209 (child of CWE-200)
- API responses leaking PII/tokens: CWE-200

## Customer-Safe Language
"Sensitive information [credential/source code/backup file] is accessible at [URL]
without authentication, potentially exposing [impact]."
"""

NOTES["cwe/cwe-287-improper-authentication.md"] = """# CWE-287: Improper Authentication — WebHound Note
CWE: 287 (class) | OWASP: A07:2021 | Severity class: High

## Description
System does not properly prove identity claims. Class-level weakness; prefer child CWEs
(CWE-306 Missing Auth for Critical Function, CWE-1390 Weak Authentication).

## WebHound Context
- Exposed admin paths without auth confirmation: CWE-306 (child)
- Login page without MFA indicator: hardening note, not CWE-287 automatically
- HTTP Basic Auth over plain HTTP: CWE-522 (credential protection) + CWE-287

## Customer-Safe Language
"Administrative or sensitive functionality may be accessible without sufficient
authentication controls, potentially allowing unauthorized access."

## Specific Trigger
Use CWE-287 class when: no authentication mechanism confirmed on sensitive page.
Do not assume improper auth from exposure alone — confirm no auth barrier exists first.
"""

NOTES["cwe/cwe-522-insufficiently-protected-credentials.md"] = """# CWE-522: Insufficiently Protected Credentials — WebHound Note
CWE: 522 | OWASP: A02:2021 Cryptographic Failures | Severity class: Medium-High

## Description
Credentials transmitted or stored without adequate protection (cleartext, weak encoding).

## WebHound Context
- HTTP form submission of credentials (not HTTPS): direct finding
- Mixed content on login/payment pages: credentials at risk of cleartext transmission
- Session cookies without Secure flag: related (CWE-614 is more specific)
- Exposed .env with plaintext passwords: CWE-522 + CWE-200

## Customer-Safe Language
"Authentication credentials may be transmitted or stored without adequate protection,
potentially exposing them to interception or unauthorized access."
"""

NOTES["cwe/cwe-611-xxe.md"] = """# CWE-611: XML External Entity (XXE) — WebHound Note
CWE: 611 | OWASP: A05:2021 Security Misconfiguration | Severity class: High

## Description
XML parsers with external entity resolution enabled allow attackers to read local files,
make server-side requests, or cause denial of service.

## WebHound Context
- Not a passive scanner finding; requires active XML payload testing
- Nuclei templates may test XXE on XML-accepting endpoints
- Relevant for: SOAP endpoints, GraphQL endpoints accepting XML, SVG upload handlers
- GraphQL exposure finding may indicate XML-adjacent risk context

## Customer-Safe Language
"XML-processing functionality may not restrict external entity references, potentially
allowing access to server-side files or triggering unintended server requests."
"""

NOTES["cwe/cwe-798-hardcoded-credentials.md"] = """# CWE-798: Hard-coded Credentials — WebHound Note
CWE: 798 | OWASP: A07:2021 Auth Failures | Severity class: Critical

## Description
Authentication credentials embedded directly in code or configuration files.
Affects all installations equally; enables mass-scale exploitation.

## WebHound Context
DIRECT scanner findings:
- Exposed .env files containing API keys/database passwords: CWE-798
- JavaScript source with embedded API tokens (third-party script risk)
- Exposed Swagger/OpenAPI definitions containing example credentials

## Customer-Safe Language
"Authentication credentials [API key/password/token] are accessible in files that
should be restricted, potentially allowing unauthorized access to [service/database]."

## Severity Note
Critical when credentials are confirmed (not just placeholder values).
Verify credentials are live before claiming Critical severity.
"""

NOTES["cwe/cwe-614-cookie-without-secure.md"] = """# CWE-614: Cookie Without Secure Flag — WebHound Note
CWE: 614 | OWASP: A05:2021 Misconfiguration | Severity class: Low-Medium

## Description
Session/authentication cookies without the Secure flag may be transmitted over HTTP,
enabling interception via network monitoring or MITM.

## WebHound Context
DIRECT scanner finding: session/auth cookies missing Secure attribute.
Common with: legacy applications, HTTP-accessible staging servers, misconfigured backends.

## Risk Factors
- Higher risk if site allows HTTP requests (not fully HTTPS-only)
- Lower risk if HSTS is enforced (HTTP requests always redirect to HTTPS)
- Severity downgrade if no sensitive data in cookie

## Customer-Safe Language
"Session cookies are configured to transmit over unencrypted connections.
Adding the Secure flag ensures cookies are sent only over HTTPS."

## Fix
Set Secure flag in cookie creation. Pair with HSTS to prevent HTTP downgrade.
"""

NOTES["cwe/cwe-1004-cookie-without-httponly.md"] = """# CWE-1004: Cookie Without HttpOnly Flag — WebHound Note
CWE: 1004 | OWASP: A05:2021 Misconfiguration | Severity class: Low-Medium

## Description
Session/auth cookies without HttpOnly flag are accessible to JavaScript,
enabling theft via XSS attacks.

## WebHound Context
DIRECT scanner finding: session/auth cookies missing HttpOnly attribute.
Risk is realized only if XSS is also present — standalone finding is lower severity.

## Customer-Safe Language
"Session cookies do not have the HttpOnly flag set. This flag prevents JavaScript from
accessing cookies, reducing the impact of any cross-site scripting vulnerabilities."

## Fix
Set HttpOnly flag on all sensitive cookies. Combine with Secure and SameSite=Strict/Lax.
"""

NOTES["cwe/cwe-1021-clickjacking-ui-redress.md"] = """# CWE-1021: Clickjacking / UI Redress — WebHound Note
CWE: 1021 | OWASP: A05:2021 Misconfiguration | Severity class: Low-Medium

## Description
Missing frame restrictions allow attackers to overlay the page in an iframe and trick
users into clicking hidden elements (clickjacking / UI redress attacks).

## WebHound Context
DIRECT scanner finding: missing X-Frame-Options or CSP frame-ancestors header.
Specific risk on pages with consequential click actions (payment confirm, permissions, delete).

## Customer-Safe Language
"This page can be embedded in a frame on another website. An attacker could overlay
deceptive content to trick visitors into unintended actions (clickjacking)."

## Fix Priority
- Sensitive pages (account settings, payment): High priority
- General content pages: Low priority
- Use CSP frame-ancestors (preferred) or X-Frame-Options: DENY/SAMEORIGIN
"""

NOTES["cwe/cwe-693-protection-mechanism-failure.md"] = """# CWE-693: Protection Mechanism Failure — WebHound Note
CWE: 693 (pillar; DISCOURAGED for direct mapping) | OWASP: A05:2021 | Severity class: varies

## Description
Pillar-level weakness for absent, insufficient, or inconsistently applied security defenses.
Parent of many specific CWEs including missing security headers.

## WebHound Use
Use CWE-693 only as an abstract class reference when describing the CATEGORY of missing
security headers collectively. For individual findings, use more specific CWEs:
- Missing CSP -> CWE-1021 (clickjacking) as one consequence, or CWE-16 (config)
- Missing HSTS -> CWE-319 (cleartext transmission)
- Missing X-Frame-Options -> CWE-1021

## Customer-Safe Language
"Several standard browser security mechanisms are not enabled on this site.
These controls reduce exposure to common web attacks."
"""

for rel_path, content in NOTES.items():
    abs_path = os.path.join(KT, rel_path.replace("/", os.sep))
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Done: {len(NOTES)} knowledge notes (part 1: READMEs + CWE notes)")
