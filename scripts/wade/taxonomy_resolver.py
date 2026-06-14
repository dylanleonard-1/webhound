"""Phase 8B: WADE retrieval taxonomy resolver.

Maps 22 finding categories to CWE, OWASP, and severity guidance text.
Advisory only — does NOT modify production finding severity.
"""
from __future__ import annotations

# 22 finding categories → {cwe, cwe_name, owasp, severity_guidance, query}
TAXONOMY_MAP: dict[str, dict[str, str]] = {
    "missing_csp": {
        "cwe": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Medium — CSP prevents XSS execution; absence raises residual XSS risk.",
        "query": "Content Security Policy CSP missing header browser protection XSS",
    },
    "missing_hsts": {
        "cwe": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "Medium — HSTS prevents protocol downgrade; absence enables MITM on first visit.",
        "query": "HSTS strict transport security header missing HTTPS downgrade",
    },
    "missing_x_frame_options": {
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Medium — X-Frame-Options or CSP frame-ancestors mitigates clickjacking.",
        "query": "X-Frame-Options clickjacking frame header missing",
    },
    "missing_secure_cookie": {
        "cwe": "CWE-614",
        "cwe_name": "Sensitive Cookie in HTTPS Session Without Secure Attribute",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "Medium — cookies without Secure flag may be sent over HTTP.",
        "query": "cookie Secure attribute flag missing HTTPS session",
    },
    "missing_httponly_cookie": {
        "cwe": "CWE-1004",
        "cwe_name": "Sensitive Cookie Without HttpOnly Flag",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Medium — HttpOnly prevents JavaScript access to session cookies.",
        "query": "cookie HttpOnly flag missing JavaScript access session hijack",
    },
    "missing_samesite_cookie": {
        "cwe": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery (CSRF)",
        "owasp": "A01:2021 Broken Access Control",
        "severity_guidance": "Medium — SameSite=Strict/Lax reduces CSRF risk.",
        "query": "cookie SameSite attribute CSRF cross-site request forgery",
    },
    "mixed_content": {
        "cwe": "CWE-311",
        "cwe_name": "Missing Encryption of Sensitive Data",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "Medium — active mixed content (scripts, iframes) is blocked by browsers; passive is not.",
        "query": "mixed content HTTP HTTPS resource browser blocking",
    },
    "third_party_script_risk": {
        "cwe": "CWE-829",
        "cwe_name": "Inclusion of Functionality from Untrusted Control Sphere",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "severity_guidance": "High — third-party scripts execute with full page access.",
        "query": "third-party script risk supply chain CDN integrity check",
    },
    "suspicious_javascript": {
        "cwe": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation (XSS)",
        "owasp": "A03:2021 Injection",
        "severity_guidance": "High — suspicious JS changes may indicate compromise or unauthorized modification.",
        "query": "suspicious JavaScript change compromise injection XSS script",
    },
    "threat_intel_match": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "owasp": "A09:2021 Security Logging and Monitoring Failures",
        "severity_guidance": "High — TI match on IP/domain requires investigation; shared CDN IPs may produce FPs.",
        "query": "threat intelligence IP reputation GreyNoise AbuseIPDB match",
    },
    "provider_blocked_scan": {
        "cwe": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Info — scan blocked by WAF/CDN; coverage gap, not a finding.",
        "query": "WAF blocked scan CDN challenge page access denied",
    },
    "cloudflare_challenge_page": {
        "cwe": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Info — Cloudflare challenge pages are expected WAF behavior, not vulnerabilities.",
        "query": "Cloudflare WAF challenge page 1020 block bot protection",
    },
    "vercel_deployment_protection": {
        "cwe": "CWE-284",
        "cwe_name": "Improper Access Control",
        "owasp": "A01:2021 Broken Access Control",
        "severity_guidance": "Info — Vercel deployment protection is a security control; preview auth gate is expected.",
        "query": "Vercel deployment protection preview auth gate scanner",
    },
    "exposed_env": {
        "cwe": "CWE-312",
        "cwe_name": "Cleartext Storage of Sensitive Information",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "Critical — exposed .env files disclose credentials and configuration.",
        "query": "exposed .env environment file secrets credentials disclosure",
    },
    "exposed_git": {
        "cwe": "CWE-538",
        "cwe_name": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "High — exposed .git directory leaks source code and history.",
        "query": "exposed .git directory source code disclosure version control",
    },
    "exposed_backup_file": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "High — backup files may contain credentials, DB dumps, or source.",
        "query": "backup file exposed disclosure .bak .sql .zip source code",
    },
    "wordpress_xmlrpc": {
        "cwe": "CWE-749",
        "cwe_name": "Exposed Dangerous Method or Function",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity_guidance": "Medium — XML-RPC can be abused for brute force or SSRF.",
        "query": "WordPress XML-RPC xmlrpc.php brute force SSRF disable",
    },
    "graphql_exposure": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "owasp": "A01:2021 Broken Access Control",
        "severity_guidance": "Medium-High — exposed GraphQL introspection leaks schema and may enable over-fetching.",
        "query": "GraphQL introspection exposure API schema unauthorized",
    },
    "swagger_exposure": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "owasp": "A01:2021 Broken Access Control",
        "severity_guidance": "Medium — publicly accessible Swagger/OpenAPI docs expose endpoint structure.",
        "query": "Swagger OpenAPI exposure API documentation unauthorized",
    },
    "tls_expiry": {
        "cwe": "CWE-295",
        "cwe_name": "Improper Certificate Validation",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "High — expired TLS certificate causes browser warnings; breaks HTTPS for users.",
        "query": "TLS certificate expiry expired HTTPS browser warning",
    },
    "tls_misconfiguration": {
        "cwe": "CWE-326",
        "cwe_name": "Inadequate Encryption Strength",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity_guidance": "Medium-High — weak cipher suites or deprecated protocols (TLS 1.0/1.1) reduce security.",
        "query": "TLS misconfiguration weak cipher suite deprecated protocol",
    },
    "api_exposure": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "owasp": "A01:2021 Broken Access Control",
        "severity_guidance": "Medium — publicly accessible API endpoints without authentication.",
        "query": "API endpoint exposure unauthorized access REST unauthenticated",
    },
}

SUPPORTED_FINDING_TYPES: frozenset[str] = frozenset(TAXONOMY_MAP)


def resolve_taxonomy(finding_type: str) -> dict[str, str]:
    """Return CWE, OWASP, severity guidance, and search query for a finding type."""
    return TAXONOMY_MAP.get(finding_type, {
        "cwe": "CWE-unknown",
        "cwe_name": "Unknown",
        "owasp": "Unknown",
        "severity_guidance": "No taxonomy mapping available for this finding type.",
        "query": finding_type.replace("_", " "),
    })
