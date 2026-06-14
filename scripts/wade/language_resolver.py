"""Phase 8B: WADE retrieval customer-safe language resolver.

Returns customer-facing risk summaries and remediation guidance for each
finding type. Advisory only — does NOT modify production report text.
"""
from __future__ import annotations

# finding_type → {risk_summary: str, remediation: str, escalation_note: str}
CUSTOMER_LANGUAGE: dict[str, dict[str, str]] = {
    "missing_csp": {
        "risk_summary": (
            "Your site does not send a Content Security Policy header. "
            "Without CSP, browsers cannot enforce restrictions on which scripts, "
            "styles, and resources are allowed to run. This increases your exposure "
            "to cross-site scripting (XSS) attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy response header. Start with a permissive "
            "policy (e.g., default-src 'self') and tighten it over time using a "
            "report-only mode to identify violations before enforcing."
        ),
        "escalation_note": "Escalate if active XSS is confirmed via DalFox or other active scanner.",
    },
    "missing_hsts": {
        "risk_summary": (
            "Your site does not enforce HTTP Strict Transport Security (HSTS). "
            "Without HSTS, users who visit your site over HTTP on their first visit "
            "are vulnerable to protocol-downgrade attacks that could expose session data."
        ),
        "remediation": (
            "Add a Strict-Transport-Security header: "
            "'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
            "Submit to the HSTS preload list for maximum protection."
        ),
        "escalation_note": "Confirm HTTPS is properly configured before enabling HSTS.",
    },
    "missing_x_frame_options": {
        "risk_summary": (
            "Your site does not restrict being loaded inside an iframe. "
            "This can allow attackers to overlay your site inside a deceptive page "
            "and trick users into performing unintended actions (clickjacking)."
        ),
        "remediation": (
            "Add either 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive "
            "to prevent your site from being embedded in third-party iframes."
        ),
        "escalation_note": "Check if CSP frame-ancestors is already set before flagging.",
    },
    "missing_secure_cookie": {
        "risk_summary": (
            "One or more cookies on your site are missing the Secure attribute. "
            "Without Secure, cookies can be transmitted over unencrypted HTTP connections, "
            "exposing session data to network interception."
        ),
        "remediation": (
            "Set the Secure attribute on all cookies that contain session data or "
            "authentication tokens: Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax"
        ),
        "escalation_note": "Analytics cookies without Secure are lower priority than auth cookies.",
    },
    "missing_httponly_cookie": {
        "risk_summary": (
            "One or more cookies on your site are missing the HttpOnly attribute. "
            "JavaScript can read these cookies, meaning an XSS vulnerability could "
            "allow an attacker to steal session cookies and hijack accounts."
        ),
        "remediation": (
            "Set the HttpOnly attribute on all session and authentication cookies. "
            "Cookies that must be read by JavaScript (e.g., UI state) may be exempt, "
            "but session tokens should always use HttpOnly."
        ),
        "escalation_note": "Pair with XSS findings — HttpOnly matters most when XSS risk is high.",
    },
    "missing_samesite_cookie": {
        "risk_summary": (
            "One or more cookies on your site do not set the SameSite attribute. "
            "Without SameSite, cookies may be sent in cross-site requests, increasing "
            "the risk of cross-site request forgery (CSRF) attacks."
        ),
        "remediation": (
            "Set SameSite=Lax or SameSite=Strict on all cookies that do not require "
            "cross-site access. For third-party cookies, use SameSite=None; Secure."
        ),
        "escalation_note": "SameSite=Lax is the browser default since Chrome 80; flag only explicit None.",
    },
    "mixed_content": {
        "risk_summary": (
            "Your HTTPS site loads resources (images, scripts, or iframes) over HTTP. "
            "Active mixed content (scripts, iframes) is blocked by modern browsers. "
            "Passive mixed content (images, video) is still loaded but can be intercepted."
        ),
        "remediation": (
            "Update all resource URLs to use HTTPS. Check for hardcoded http:// URLs "
            "in HTML templates, CSS, and JavaScript. Add a "
            "'Content-Security-Policy: upgrade-insecure-requests' header as a fallback."
        ),
        "escalation_note": "Active mixed content (scripts, stylesheets) is higher severity than images.",
    },
    "third_party_script_risk": {
        "risk_summary": (
            "Your site loads JavaScript from third-party domains. If any of these "
            "providers are compromised or misconfigured, they can execute arbitrary "
            "JavaScript on your site with full access to your users' sessions and data."
        ),
        "remediation": (
            "Audit all third-party scripts. Add Subresource Integrity (SRI) hashes to "
            "script tags where possible. Restrict allowed script origins via CSP "
            "script-src directive."
        ),
        "escalation_note": "Escalate if unknown or unrecognized script domains are found.",
    },
    "suspicious_javascript": {
        "risk_summary": (
            "WebHound detected JavaScript that has changed unexpectedly or contains "
            "patterns associated with malicious code. This may indicate a supply chain "
            "compromise, unauthorized script injection, or skimming malware."
        ),
        "remediation": (
            "Review the flagged JavaScript immediately. Compare against known-good versions. "
            "Engage your security team for forensic investigation if the change is "
            "unauthorized. Consider activating your incident response plan."
        ),
        "escalation_note": "This is a high-priority finding requiring manual review before escalation.",
    },
    "threat_intel_match": {
        "risk_summary": (
            "An IP address or domain associated with your site has been flagged by one "
            "or more threat intelligence services. This may indicate malicious hosting, "
            "shared infrastructure with known threat actors, or a compromised CDN node."
        ),
        "remediation": (
            "Investigate the flagged IP/domain. If it is a shared CDN IP (Cloudflare, "
            "Fastly, Akamai), this may be a false positive. If it is your origin server, "
            "review access logs and assess whether the infrastructure has been compromised."
        ),
        "escalation_note": "Shared CDN IPs frequently appear in TI feeds; confirm before escalating.",
    },
    "provider_blocked_scan": {
        "risk_summary": (
            "The WebHound scanner was blocked by a Web Application Firewall (WAF) or "
            "CDN security rule when attempting to assess your site. This means scan "
            "coverage is incomplete and some findings may have been missed."
        ),
        "remediation": (
            "If you are using Cloudflare, Imperva, or another WAF, consider allowlisting "
            "the WebHound scanner IP range to enable complete coverage, or use WebHound's "
            "provider-aware scan mode for WAF-managed sites."
        ),
        "escalation_note": "This is a coverage gap, not a vulnerability in your application.",
    },
    "cloudflare_challenge_page": {
        "risk_summary": (
            "WebHound encountered a Cloudflare challenge page while scanning your site. "
            "This is expected if you have Bot Fight Mode or Under Attack Mode enabled. "
            "Scan coverage may be incomplete for pages behind the challenge."
        ),
        "remediation": (
            "To enable full scan coverage, temporarily allowlist the WebHound scanner in "
            "your Cloudflare security settings, or use a bypass rule scoped to the "
            "scanner's user agent or IP."
        ),
        "escalation_note": "Cloudflare challenge is a security control — do not disable it permanently.",
    },
    "vercel_deployment_protection": {
        "risk_summary": (
            "The scanned URL appears to be a Vercel preview deployment with deployment "
            "protection enabled. The scanner received an authentication gate instead of "
            "the application, limiting scan coverage."
        ),
        "remediation": (
            "For full scan coverage of preview environments, use a bypass token or "
            "configure a WebHound-specific bypass in your Vercel project settings "
            "under Settings > Deployment Protection."
        ),
        "escalation_note": "This affects preview URLs only; production deployments are typically unaffected.",
    },
    "exposed_env": {
        "risk_summary": (
            "Your site is serving an environment configuration file (.env) publicly. "
            "These files typically contain database credentials, API keys, and other "
            "secrets. This is a critical security exposure requiring immediate action."
        ),
        "remediation": (
            "Immediately remove the .env file from your public web root. Rotate ALL "
            "credentials and API keys that may have been exposed. Review access logs "
            "to determine if the file was downloaded. "
            "Never store .env files in publicly accessible directories."
        ),
        "escalation_note": "CRITICAL — treat this as a confirmed credential leak. Rotate all secrets immediately.",
    },
    "exposed_git": {
        "risk_summary": (
            "Your web server is exposing the .git directory publicly. This allows "
            "anyone to download your entire source code history, including any "
            "secrets, credentials, or sensitive data that was ever committed."
        ),
        "remediation": (
            "Block access to the .git directory via your web server configuration "
            "(e.g., Nginx 'deny all' for /.git/). Consider rotating any secrets "
            "that may have been present in git history. Use 'git log' to audit for "
            "committed credentials."
        ),
        "escalation_note": "Review git history for committed secrets before treating as remediated.",
    },
    "exposed_backup_file": {
        "risk_summary": (
            "Your site appears to be exposing backup or archive files in a publicly "
            "accessible location. These files may contain source code, database dumps, "
            "configuration files, or other sensitive data."
        ),
        "remediation": (
            "Remove backup files from your web root or restrict access via server "
            "configuration. Review what data the files contain. If database credentials "
            "or API keys are present, rotate them immediately."
        ),
        "escalation_note": "Severity depends on file contents — database dumps and source archives are highest risk.",
    },
    "wordpress_xmlrpc": {
        "risk_summary": (
            "Your WordPress site has XML-RPC (xmlrpc.php) enabled. XML-RPC can be "
            "exploited for credential brute-force attacks, DDoS amplification via "
            "multicall, and in some configurations, Server-Side Request Forgery (SSRF)."
        ),
        "remediation": (
            "Disable XML-RPC if it is not actively required by a plugin. In WordPress, "
            "this can be done via the functions.php file or a security plugin. "
            "If Jetpack requires it, restrict access to Automattic's IP ranges only."
        ),
        "escalation_note": "Confirm xmlrpc.php returns 200 with method list before flagging.",
    },
    "graphql_exposure": {
        "risk_summary": (
            "Your site exposes a GraphQL endpoint with introspection enabled. "
            "Introspection allows anyone to enumerate your entire API schema, "
            "including all types, queries, and mutations, which aids attackers "
            "in identifying attack surfaces."
        ),
        "remediation": (
            "Disable GraphQL introspection in production. Enforce authentication on "
            "all GraphQL endpoints. Implement query depth and complexity limits to "
            "prevent resource exhaustion attacks."
        ),
        "escalation_note": "Public read-only APIs with introspection may be intentional — assess context.",
    },
    "swagger_exposure": {
        "risk_summary": (
            "Your site exposes API documentation (Swagger/OpenAPI) without access "
            "controls. This allows anyone to enumerate your API endpoints, parameters, "
            "and data models, reducing the effort required for targeted attacks."
        ),
        "remediation": (
            "Restrict access to API documentation to authenticated users or internal "
            "networks. If the API docs are intentionally public, ensure that no "
            "sensitive endpoint details or internal URLs are included."
        ),
        "escalation_note": "Assess whether documentation reveals authentication endpoints or sensitive operations.",
    },
    "tls_expiry": {
        "risk_summary": (
            "Your site's TLS/SSL certificate has expired or will expire shortly. "
            "An expired certificate causes browsers to display security warnings, "
            "blocking access for most users and damaging trust in your service."
        ),
        "remediation": (
            "Renew your TLS certificate immediately. Consider using a CDN with "
            "automatic certificate management (Cloudflare, Let's Encrypt with auto-renew) "
            "to prevent future expiry. Set up monitoring alerts for certificate expiry."
        ),
        "escalation_note": "CDN-managed certificates auto-renew; verify if scanner observed CDN or origin cert.",
    },
    "tls_misconfiguration": {
        "risk_summary": (
            "Your site's TLS configuration uses deprecated or weak settings. "
            "This may include TLS 1.0 or 1.1 support, weak cipher suites, or "
            "missing TLS features, reducing the protection of encrypted connections."
        ),
        "remediation": (
            "Disable TLS 1.0 and 1.1. Configure your server to support only TLS 1.2+ "
            "with strong cipher suites (e.g., TLS_AES_128_GCM_SHA256). "
            "Use Mozilla's SSL Config Generator for reference configurations."
        ),
        "escalation_note": "Legacy TLS may be required by specific client contracts — confirm before remediation.",
    },
    "api_exposure": {
        "risk_summary": (
            "WebHound detected API endpoints that appear to be accessible without "
            "authentication or authorization controls. Unauthenticated API access "
            "may expose sensitive data or allow unauthorized operations."
        ),
        "remediation": (
            "Implement authentication (OAuth 2.0, API keys, or JWT) on all API "
            "endpoints that return or accept sensitive data. Apply the principle of "
            "least privilege: endpoints should only be accessible to roles that need them."
        ),
        "escalation_note": "Health check and well-known endpoints may be intentionally public — review scope.",
    },
}

# Short risk label per finding type
FINDING_RISK_SUMMARY: dict[str, str] = {
    ft: data["risk_summary"][:100] + "..."
    for ft, data in CUSTOMER_LANGUAGE.items()
}


def resolve_customer_language(finding_type: str) -> dict[str, str]:
    """Return risk_summary, remediation, and escalation_note for a finding type."""
    return CUSTOMER_LANGUAGE.get(finding_type, {
        "risk_summary": f"A security issue of type '{finding_type}' was detected.",
        "remediation": "Consult your security team to investigate and remediate this finding.",
        "escalation_note": "No specific escalation guidance available for this finding type.",
    })


def resolve_risk_summary(finding_type: str) -> str:
    """Return just the risk summary string."""
    return resolve_customer_language(finding_type)["risk_summary"]


def resolve_remediation(finding_type: str) -> str:
    """Return just the remediation guidance string."""
    return resolve_customer_language(finding_type)["remediation"]
