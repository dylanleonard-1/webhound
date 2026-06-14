"""Phase 6F: Write CWE normalized files (extracted from MITRE CWE official pages)."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASE = os.path.join(ROOT, "corpus", "normalized", "vulnerability-taxonomy", "cwe")
os.makedirs(BASE, exist_ok=True)

FILES = {
"pd-vt-cwe--overview.md": """# CWE Program — Extracted Reference
source: https://cwe.mitre.org/about/index.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## What CWE Is
Common Weakness Enumeration (CWE) is a community-developed list of common software and
hardware weaknesses. A weakness is a condition that, under certain circumstances, could
contribute to the introduction of vulnerabilities. CWE provides identifiers (CWE IDs)
for each weakness type, enabling consistent communication across tools and organizations.

## Weakness vs Vulnerability
- Weakness: a latent flaw (a category/class of defect)
- Vulnerability: an exploitable instance of a weakness in specific software (tracked by CVE)
- CWE classifies the root cause; CVE identifies the specific occurrence.

## Organization
CWE uses "Views" to organize weaknesses by context:
- Software Development View: concepts relevant during development
- Hardware Design View: hardware-specific weaknesses
- Research Concepts View: behavioral characteristics for research

## Governance
Sponsored by DHS CISA; managed by HSSEDI, operated by MITRE Corporation.
Updated 3-4 times per year. Freely usable for research, education, tools.
REST API available for programmatic access.

## Relationship to NVD and CVE
CWE IDs are assigned to CVE records in the NVD as the root-cause weakness.
One CVE can map to one or more CWEs. CWE mappings help pattern analysis
(e.g., CWE Top 25 identifies the most commonly exploited weakness categories).
""",

"pd-vt-cwe--79-xss.md": """# CWE-79 — Cross-Site Scripting (XSS)
source: https://cwe.mitre.org/data/definitions/79.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Type
Base-level weakness; technology-independent; suitable for detection and mapping.

## Description
Occurs when applications fail to neutralize user-controllable input before placing it
in web page output. Attackers inject scripts executed in other users' browsers.

## Attack Types
- Reflected XSS: malicious content in URL/request, reflected immediately
- Stored XSS: malicious data persisted in database, later served to users
- DOM-based XSS: client-side JavaScript unsafely manipulates the DOM

## Common Consequences
- Steal session cookies and authentication tokens
- Execute unauthorized code/scripts in victim browser
- Manipulate page content; credential harvesting

## Mitigations
- Output encoding: encode all non-alphanumeric characters based on context (HTML/attr/URI/JS)
- Input validation: allowlist-based; validate all request components
- Trusted libraries: OWASP ESAPI, Microsoft Anti-XSS
- HttpOnly cookies: prevents script access to session cookies
- Content Security Policy: reduces XSS impact

## WebHound Relevance
Applies to: third-party scripts injecting content, suspicious JS obfuscation findings.
Not a direct scanner finding — context-dependent. Map to OWASP A03:2021 Injection.
""",

"pd-vt-cwe--89-sqli.md": """# CWE-89 — SQL Injection
source: https://cwe.mitre.org/data/definitions/89.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Type
Base-level weakness.

## Description
Product constructs SQL commands using externally-influenced input without properly
neutralizing special elements. Attackers modify the query structure.

## Common Consequences
- Execute unauthorized commands; read/modify/delete data
- Bypass authentication (login bypass)
- Privilege escalation via stored authorization tables
- Confidentiality, integrity, and availability impact

## Mitigations
- Parameterized queries / prepared statements (primary defense)
- Input validation with strict allowlists
- Least privilege on database accounts
- Vetted ORM frameworks (Hibernate, etc.)
- Minimize error message detail to prevent information leakage

## WebHound Relevance
Indirect: scanner passive checks may detect forms suggesting SQLi risk.
Map to OWASP A03:2021 Injection. CVE assignment requires a specific vulnerable product version.
""",

"pd-vt-cwe--352-csrf.md": """# CWE-352 — Cross-Site Request Forgery (CSRF)
source: https://cwe.mitre.org/data/definitions/352.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Cross-Site Request Forgery (CSRF)

## Description
Application does not sufficiently verify that requests are intentionally provided by
the authenticated user. Attacker tricks user into submitting forged requests.

## Modes of Introduction
Architecture and design phase: failure to implement request verification.

## Consequences
- Unauthorized data modification
- Privilege escalation
- Information disclosure
- Denial of service
- Administrator-level CSRF = full application takeover

## Mitigations
- Unpredictable CSRF tokens per session/form; validate server-side
- Double-submitted cookies pattern
- SameSite cookie attribute (Strict or Lax)
- Referer header validation (privacy-sensitive)
- Explicit user confirmation for sensitive operations

## WebHound Relevance
Missing CSRF protection on forms = weakness finding, not a CVE unless tied to a product.
SameSite=None without Secure on session cookies is related finding.
""",

"pd-vt-cwe--22-path-traversal.md": """# CWE-22 — Path Traversal
source: https://cwe.mitre.org/data/definitions/22.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
Failure to properly validate external input used to construct file paths. Attackers use
special characters (../, absolute paths) to traverse outside intended directories.

## Consequences
- Execute unauthorized code (overwrite executables)
- Modify/create critical files
- Read sensitive data (credentials, configs)
- Denial of service (delete critical files)

## Mitigations
- Input validation: allowlist-based; exclude directory separators
- Path canonicalization: realpath() / getCanonicalPath() / GetFullPath() before validation
- Least privilege: minimize file access permissions
- Map user input to fixed filenames rather than accepting arbitrary paths
- Sandbox / chroot environments

## WebHound Relevance
Exposed sensitive files (.env, .git, backup files) are related to path exposure findings.
Nuclei/ZAP findings about exposed paths may indicate path traversal risk on server.
Not auto-CVE — requires specific vulnerable application identification.
""",

"pd-vt-cwe--78-cmdi.md": """# CWE-78 — OS Command Injection
source: https://cwe.mitre.org/data/definitions/78.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Description
Product constructs OS commands using externally-influenced input without neutralizing
special elements. Allows attacker to modify commands sent to downstream OS components.

## Consequences
- Execute unauthorized operating system commands
- Read and modify data; disable the product
- Malicious activity appears to originate from the compromised application

## Mitigations
- Use libraries instead of external processes when possible
- Strict allowlist input validation
- Proper output encoding and escaping of shell arguments
- Use parameterized command execution (execl() not system())
- Least privilege; sandboxing (chroot, AppArmor, SELinux)

## WebHound Relevance
Generally not a direct WebHound scanner finding (passive scan). If server-side injection
indicators are detected (via Nuclei active testing), may surface as high-severity finding.
""",

"pd-vt-cwe--918-ssrf.md": """# CWE-918 — Server-Side Request Forgery (SSRF)
source: https://cwe.mitre.org/data/definitions/918.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Server-Side Request Forgery (SSRF)

## Description
Web server receives a URL or request from upstream and retrieves it without
sufficiently ensuring the request goes to the expected destination.

## Consequences
- Confidentiality: access to internal systems/services
- Integrity: execute unauthorized code on behalf of compromised server
- Bypass access controls (firewalls, network segmentation)
- Port scanning of internal networks via file:// or alternative protocols

## Mitigations
- Allowlist of approved URLs/domains; reject anything outside
- Strict input validation on user-supplied URLs
- Block outbound requests to internal RFC-1918 ranges
- Disable unnecessary URL scheme handlers (file://, gopher://, etc.)

## WebHound Relevance
CWE Top 25; OWASP Top 10 2021 A10. Relevant when scanner detects server-side
URL fetch functionality (open redirect, webhook endpoints). Not auto-CVE.
""",

"pd-vt-cwe--200-info-exposure.md": """# CWE-200 — Exposure of Sensitive Information to Unauthorized Actor
source: https://cwe.mitre.org/data/definitions/200.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Exposure of Sensitive Information to an Unauthorized Actor

## Type
Class-level weakness (DISCOURAGED for direct mapping — use more specific child CWEs).

## Description
Product reveals sensitive information to actors not authorized to access it. Manifests as:
- Code explicitly inserting sensitive data into accessible resources
- Other weaknesses indirectly causing exposure (e.g., verbose error messages)
- Resources with sensitive data becoming unintentionally accessible

## Consequences
- Loss of confidentiality: unauthorized reading of application data
- Enables follow-on attacks (credential harvest, enumeration)

## Mitigations
- Separation of privilege; compartmentalized system design
- Sanitize error messages before display (no stack traces, SQL errors to users)
- Least privilege on resource access
- Avoid storing sensitive information in publicly accessible resources

## WebHound Relevance
Directly relevant: exposed .env, .git, backup files, sensitive paths.
Use more specific child weakness when possible (e.g., CWE-209 for error messages).
Mapping CWE-200 to "exposed .env" is acceptable at the class level.
""",

"pd-vt-cwe--287-improper-auth.md": """# CWE-287 — Improper Authentication
source: https://cwe.mitre.org/data/definitions/287.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Authentication

## Type
Class-level weakness (DISCOURAGED for direct mapping — prefer child CWEs like CWE-306).

## Description
When an actor claims an identity, the product does not prove or insufficiently proves
that the claim is correct. Encompasses all forms of authentication failure.

## Consequences
- Unauthorized access to resources and functionality
- Read sensitive data, assume false identities
- Execute unauthorized commands

## Mitigations
- Use vetted authentication frameworks (OWASP ESAPI, platform-provided auth)
- Multi-factor authentication
- Strong session management (secure, HttpOnly, short-lived tokens)

## WebHound Relevance
Exposed admin paths, login pages without MFA indicators, insecure session cookies.
Use CWE-306 (Missing Auth for Critical Function) for specific admin exposure findings.
""",

"pd-vt-cwe--522-protected-creds.md": """# CWE-522 — Insufficiently Protected Credentials
source: https://cwe.mitre.org/data/definitions/522.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Insufficiently Protected Credentials

## Description
Authentication credentials are transmitted or stored using insecure methods allowing
unauthorized interception or retrieval. Includes cleartext storage, weak encoding,
and unprotected transmission.

## Consequences
- Unauthorized access to user accounts
- Identity theft; follow-on credential stuffing

## Mitigations
- Architectural: purpose-built credential protection mechanisms
- Cryptographic protection for stored credentials (strong hashing: bcrypt, Argon2)
- Encrypted transmission (TLS for all credential exchanges)
- LDAP or keystore implementations for enterprise credential management

## WebHound Relevance
Related to: insecure cookies (cleartext session tokens), HTTP (not HTTPS) form submission,
credentials visible in API responses. Mixed content findings where credentials could be
transmitted over HTTP.
""",

"pd-vt-cwe--798-hardcoded-creds.md": """# CWE-798 — Use of Hard-coded Credentials
source: https://cwe.mitre.org/data/definitions/798.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Use of Hard-coded Credentials

## Description
Product contains embedded authentication credentials (passwords, cryptographic keys).
Two variants: inbound (default accounts with unchangeable passwords) and outbound
(back-end credentials embedded in front-end code).

## Consequences
- Attackers almost certainly gain access when credentials are discovered
- Shared across all installations — enables mass-scale attacks/worms
- Compromise of confidentiality, integrity, availability

## Mitigations
- Store credentials outside code in encrypted config files or secrets managers
- For inbound: first-login mode requiring unique strong password
- Strong one-way hashes for stored passwords (bcrypt, Argon2)
- Automatically rotating credentials with time-sensitive validation

## WebHound Relevance
Exposed .env files, exposed configuration files with credentials.
JavaScript source code containing API keys/tokens (third-party script risk finding).
High severity when confirmed. Likelihood of exploitation: high.
""",

"pd-vt-cwe--611-xxe.md": """# CWE-611 — XML External Entity (XXE)
source: https://cwe.mitre.org/data/definitions/611.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Restriction of XML External Entity Reference

## Description
XML processors fail to restrict external entity references. Attackers craft XML documents
with entities resolving to unintended resources (local files, internal URLs).

## Consequences
- Data breach: access arbitrary files (file:// URIs in entity references)
- Security bypass: force outbound HTTP requests via crafted DTDs (SSRF-like)
- Denial of service: entity references to large files or infinite recursion

## Mitigations
- Disable external entity processing in XML parsers (primary defense)
- Use configuration options to prevent DTD loading
- Input validation on XML content before parsing

## WebHound Relevance
Relevant when customer sites process XML (API endpoints, SOAP, SVG uploads).
Not a passive-scan finding but may appear in Nuclei/ZAP active testing.
OWASP Top 10 2017 A04; part of OWASP 2021 A05 Security Misconfiguration.
""",

"pd-vt-cwe--614-cookie-no-secure.md": """# CWE-614 — Cookie Without Secure Flag
source: https://cwe.mitre.org/data/definitions/614.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

## Description
The Secure attribute for sensitive cookies in HTTPS sessions is not set. Without it,
user agents may transmit cookies over unencrypted HTTP connections.

## Consequences
- Confidentiality: cookies transmitted in plaintext over HTTP sessions
- Session sidejacking (CAPEC-102) via network interception or MITM

## Mitigations
- Always set Secure attribute on cookies containing sensitive data
- In Java: setSecure(true) before adding cookie to response
- Pair with HSTS to prevent HTTP downgrade attacks

## WebHound Relevance
Direct scanner finding: missing Secure flag on session/auth cookies.
Map to OWASP A05:2021 Security Misconfiguration. Severity: Medium (requires network position).
Not auto-CVE; configure-and-harden finding.
""",

"pd-vt-cwe--1004-cookie-no-httponly.md": """# CWE-1004 — Cookie Without HttpOnly Flag
source: https://cwe.mitre.org/data/definitions/1004.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Sensitive Cookie Without 'HttpOnly' Flag

## Description
Product stores sensitive information in a cookie without setting the HttpOnly flag.
HttpOnly prevents client-side scripts from accessing the cookie.

## Consequences
- Confidentiality: sensitive cookie data exposed to unintended parties via JS
- Authentication compromise: session cookie theft via XSS attack
- Note: browser plugins/XMLHttpRequest may bypass HttpOnly in some cases

## Mitigations
- Set HttpOnly flag on all sensitive cookies; high effectiveness
- Combine with Secure flag and SameSite attribute for defense-in-depth

## WebHound Relevance
Direct scanner finding: missing HttpOnly on session cookies.
Map to OWASP A05:2021 Security Misconfiguration. Severity: Low-Medium (requires XSS prerequisite).
Commonly paired with CWE-614 (missing Secure flag) in cookie security reports.
""",

"pd-vt-cwe--1021-clickjacking.md": """# CWE-1021 — Clickjacking / UI Redress
source: https://cwe.mitre.org/data/definitions/1021.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Improper Restriction of Rendered UI Layers or Frames

## Description
Web application does not restrict or incorrectly restricts frame objects or UI layers
from other applications or domains. Also known as clickjacking, UI redress, tapjacking.
Attackers overlay malicious content on legitimate interfaces to trick users.

## Consequences
- Access control bypass: users deceived into performing hidden actions
- Privilege escalation, identity assumption
- Examples: changing privacy settings, granting unintended permissions

## Mitigations
- X-Frame-Options header: DENY or SAMEORIGIN
- CSP frame-ancestors directive (preferred over X-Frame-Options)
- Frame-breaking JavaScript (legacy; bypassed by nested frames)
- Restrict object/embed/applet elements as well

## WebHound Relevance
Direct scanner finding: missing X-Frame-Options or CSP frame-ancestors.
Map to OWASP A05:2021 Security Misconfiguration. Severity: Low-Medium.
Report as hardening finding; not a CVE. Customer-safe: "frames from other sites not restricted."
""",

"pd-vt-cwe--693-protection-failure.md": """# CWE-693 — Protection Mechanism Failure
source: https://cwe.mitre.org/data/definitions/693.html
live_fetch_status: ok
authority_tier: A
ingested: 2026-06-14

## Name
Protection Mechanism Failure

## Type
Pillar-level weakness — most abstract classification (DISCOURAGED for direct mapping).

## Description
Product fails to properly implement security defenses: mechanisms absent, providing
insufficient protection, or inconsistently applied across code paths.

## What It Covers (child weaknesses include)
- Missing or inadequate encryption
- Weak cryptographic algorithms
- Insufficient randomness in security functions
- Inadequate data authenticity verification
- Improper isolation or compartmentalization
- Reliance on untrusted inputs in security decisions

## Consequences
Bypass protection mechanisms; attackers circumvent intended security controls.

## WebHound Relevance
Parent class for: Missing CSP, Missing HSTS, missing security headers generally.
Use more specific child CWE when possible. CSP absence could be CWE-693 (abstract)
or specifically CWE-1021 (clickjacking) / CWE-116 (encoding issues).
""",
}

for fname, content in FILES.items():
    path = os.path.join(BASE, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  wrote: corpus/normalized/vulnerability-taxonomy/cwe/{fname}")

print(f"Done: {len(FILES)} CWE normalized files")
