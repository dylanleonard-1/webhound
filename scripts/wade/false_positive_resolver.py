"""Phase 8B: WADE retrieval false-positive pattern resolver.

Returns known FP patterns and retrieval queries for each finding type.
Advisory only — does NOT modify production suppression logic.
"""
from __future__ import annotations

# finding_type → {patterns: [...], query: str, notes: str}
FP_PATTERN_MAP: dict[str, dict] = {
    "missing_csp": {
        "patterns": [
            "CDN-injected CSP headers (Cloudflare, Fastly, Akamai) may satisfy CSP requirement",
            "Meta-tag CSP is not detected by header-only scanners",
        ],
        "query": "CSP missing header false positive CDN injected content-security-policy",
        "notes": "Verify CSP is not set via meta tag before reporting.",
    },
    "missing_hsts": {
        "patterns": [
            "CDN providers (Cloudflare, Fastly) inject HSTS on their edge — scanner may not observe it",
            "HSTS only meaningful over HTTPS — verify site supports HTTPS",
        ],
        "query": "HSTS missing header false positive CDN injected strict-transport-security",
        "notes": "Confirm scanner connected over HTTPS and CDN HSTS not active.",
    },
    "missing_x_frame_options": {
        "patterns": [
            "CSP frame-ancestors directive replaces X-Frame-Options — check CSP before flagging",
        ],
        "query": "X-Frame-Options missing false positive CSP frame-ancestors alternative",
        "notes": "Check for CSP frame-ancestors before flagging missing X-Frame-Options.",
    },
    "missing_secure_cookie": {
        "patterns": [
            "Analytics/marketing cookies without Secure flag are low-risk (non-session)",
            "CDN-set cookies may lack Secure flag; context matters",
        ],
        "query": "cookie Secure attribute false positive analytics CDN non-session",
        "notes": "Distinguish session/auth cookies from tracking cookies.",
    },
    "missing_httponly_cookie": {
        "patterns": [
            "Client-side cookies (e.g., UI preferences, consent) legitimately need JS access",
            "Session cookies should have HttpOnly; UI-state cookies may not",
        ],
        "query": "cookie HttpOnly false positive client-side UI preference consent",
        "notes": "Only flag HttpOnly absence on auth/session cookies.",
    },
    "missing_samesite_cookie": {
        "patterns": [
            "Third-party cookies (e.g., SSO) may need SameSite=None; Lax is default in modern browsers",
        ],
        "query": "cookie SameSite false positive third-party SSO cross-site",
        "notes": "SameSite=Lax is browser default; check for explicit None without Secure.",
    },
    "mixed_content": {
        "patterns": [
            "Passive mixed content (images) is not blocked by modern browsers",
            "CDN resources may appear as HTTP in HTML but be upgraded by browsers",
        ],
        "query": "mixed content false positive passive image CDN upgrade",
        "notes": "Distinguish active (scripts/iframes) from passive (images/video) mixed content.",
    },
    "third_party_script_risk": {
        "patterns": [
            "Known analytics/marketing CDNs (Google Analytics, HubSpot) are expected",
            "SRI hash present = integrity verified; not a finding",
        ],
        "query": "third-party script false positive analytics CDN SRI integrity known vendor",
        "notes": "Check if script has SRI hash or is a known trusted vendor.",
    },
    "suspicious_javascript": {
        "patterns": [
            "A/B testing and personalization frameworks modify JS dynamically",
            "CMS plugin updates may change inline script hashes",
        ],
        "query": "suspicious JavaScript false positive A/B test CMS plugin update",
        "notes": "Correlate with deployment timeline before escalating.",
    },
    "threat_intel_match": {
        "patterns": [
            "Shared CDN IPs (Cloudflare, Fastly, Akamai) appear in GreyNoise as mass-event scanners",
            "AbuseIPDB shared-hosting IPs may flag legitimately hosted sites",
            "VirusTotal community detections can include false positives",
        ],
        "query": "threat intel match false positive shared CDN IP GreyNoise AbuseIPDB VirusTotal",
        "notes": "Shared infrastructure IPs require context before flagging as malicious.",
    },
    "provider_blocked_scan": {
        "patterns": [
            "WAF/CDN blocking the scanner is expected for bot-protected sites",
            "Cloudflare 1020, Imperva block page — these are WAF behaviors, not vulnerabilities",
        ],
        "query": "provider blocked scan WAF CDN false positive expected behavior bot protection",
        "notes": "A blocked scan indicates WAF is active; report as coverage gap, not a finding.",
    },
    "cloudflare_challenge_page": {
        "patterns": [
            "Cloudflare JS/CAPTCHA challenge is a security control, not a vulnerability",
            "HTTP 1020 Access Denied is WAF expected behavior",
        ],
        "query": "Cloudflare challenge page false positive WAF behavior 1020",
        "notes": "Cloudflare challenge pages must NOT be reported as XSS or injection findings.",
    },
    "vercel_deployment_protection": {
        "patterns": [
            "Vercel preview deployments have auth protection enabled by default",
            "401 on preview URL is expected if deployment protection is on",
        ],
        "query": "Vercel deployment protection false positive preview auth expected",
        "notes": "Confirm if the target is a preview vs production Vercel deployment.",
    },
    "exposed_env": {
        "patterns": [
            ".env files that return 404 or 403 are not exposed",
            "Some frameworks (Next.js) serve a redacted .env.example intentionally",
        ],
        "query": "exposed env false positive 404 403 redacted example file",
        "notes": "Only flag if .env returns 200 with actual key=value pairs.",
    },
    "exposed_git": {
        "patterns": [
            "Git metadata on intentional public repositories is not a finding",
            "/.git that returns 403 is not accessible",
        ],
        "query": "exposed git false positive public repository 403 forbidden",
        "notes": "Check response body for actual git objects before flagging.",
    },
    "exposed_backup_file": {
        "patterns": [
            "Some sites intentionally serve public backup listings for recovery",
            "Backup files returning 403/404 are not exposed",
        ],
        "query": "backup file false positive 403 404 public intentional",
        "notes": "Verify 200 response with readable content before flagging.",
    },
    "wordpress_xmlrpc": {
        "patterns": [
            "Some plugins require XML-RPC (e.g., Jetpack); absence of xmlrpc.php is the safe state",
            "403 on xmlrpc.php = disabled/protected, not exploitable",
        ],
        "query": "WordPress xmlrpc false positive plugin requirement Jetpack disabled",
        "notes": "Confirm 200 with XML-RPC method list before flagging.",
    },
    "graphql_exposure": {
        "patterns": [
            "Public GraphQL APIs with read-only introspection may be intentional",
            "Some APIs disable introspection in production — check environment",
        ],
        "query": "GraphQL introspection false positive public read-only intentional",
        "notes": "Evaluate whether schema exposure leaks sensitive data or enables attacks.",
    },
    "swagger_exposure": {
        "patterns": [
            "Public API documentation may be intentional for developer experience",
            "Swagger UI without sensitive endpoint details is lower risk",
        ],
        "query": "Swagger OpenAPI false positive public documentation intentional",
        "notes": "Assess whether exposed endpoints include auth-required operations.",
    },
    "tls_expiry": {
        "patterns": [
            "CDN-managed TLS (Cloudflare, Fastly) auto-renews; scanner may see CDN cert",
            "Staging environments may use expired/self-signed certificates intentionally",
        ],
        "query": "TLS expiry false positive CDN managed auto-renew staging self-signed",
        "notes": "Distinguish CDN-terminated TLS from origin TLS expiry.",
    },
    "tls_misconfiguration": {
        "patterns": [
            "Some legacy API clients require TLS 1.0/1.1 — intentional backward compatibility",
            "CDN providers may surface legacy TLS on some edge nodes",
        ],
        "query": "TLS misconfiguration false positive legacy API backward compatibility CDN",
        "notes": "Confirm whether legacy TLS is required by client contracts.",
    },
    "api_exposure": {
        "patterns": [
            "Public APIs with documented open access are not unauthorized",
            "Health check endpoints (/.well-known/, /health) are typically intentional",
        ],
        "query": "API exposure false positive public health check well-known intentional",
        "notes": "Check if endpoint is documented as public before flagging.",
    },
}


def resolve_fp_patterns(finding_type: str) -> list[str]:
    """Return list of known FP pattern strings for a finding type."""
    entry = FP_PATTERN_MAP.get(finding_type)
    if not entry:
        return [f"No specific FP patterns documented for {finding_type}."]
    return entry["patterns"]


def resolve_fp_query(finding_type: str) -> str:
    """Return the knowledge-base search query for FP patterns of a finding type."""
    entry = FP_PATTERN_MAP.get(finding_type)
    if not entry:
        return f"false positive {finding_type.replace('_', ' ')}"
    return entry["query"]


def resolve_fp_notes(finding_type: str) -> str:
    """Return investigation notes for avoiding FP on a finding type."""
    entry = FP_PATTERN_MAP.get(finding_type)
    if not entry:
        return ""
    return entry.get("notes", "")
