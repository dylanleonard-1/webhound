"""Phase 8B: WADE retrieval provider resolver.

Maps provider names and finding types to specific knowledge-base queries.
Advisory only — no production changes.
"""
from __future__ import annotations

# Provider name aliases → canonical name
PROVIDER_ALIASES: dict[str, str] = {
    "cloudflare": "cloudflare",
    "cf": "cloudflare",
    "vercel": "vercel",
    "railway": "railway",
    "fastly": "fastly",
    "akamai": "akamai",
    "aws": "aws",
    "aws-cloudfront": "aws",
    "azure": "azure",
    "imperva": "imperva",
    "sucuri": "sucuri",
    "netlify": "netlify",
    "fly": "fly.io",
    "fly.io": "fly.io",
    "render": "render",
    "stripe": "stripe",
    "resend": "resend",
    "github": "github",
    "google": "google-cloud",
    "gcp": "google-cloud",
}

# Provider → knowledge-base search terms
PROVIDER_QUERY_MAP: dict[str, str] = {
    "cloudflare": "Cloudflare WAF CDN challenge page 1020 block bot protection HSTS",
    "vercel": "Vercel deployment protection preview auth gate scanner CDN",
    "railway": "Railway deployment cloud hosting scanner",
    "fastly": "Fastly CDN edge cache header injection",
    "akamai": "Akamai CDN WAF bot manager challenge",
    "aws": "AWS CloudFront WAF 403 block CDN edge",
    "azure": "Azure CDN WAF Front Door header modification",
    "imperva": "Imperva Incapsula WAF block challenge page",
    "sucuri": "Sucuri WAF firewall CDN block page",
    "netlify": "Netlify CDN deployment headers",
    "fly.io": "Fly.io deployment cloud hosting",
    "render": "Render cloud hosting deployment",
    "stripe": "Stripe payment API security",
    "resend": "Resend email API",
    "github": "GitHub Pages CDN deployment",
    "google-cloud": "Google Cloud CDN load balancer WAF",
}

# Finding types that are inherently provider-specific
PROVIDER_FINDING_TYPES: frozenset[str] = frozenset({
    "cloudflare_challenge_page",
    "vercel_deployment_protection",
    "provider_blocked_scan",
})

# Finding type × provider → specialized query suffix
SPECIALIZED_QUERIES: dict[tuple[str, str], str] = {
    ("cloudflare_challenge_page", "cloudflare"): (
        "Cloudflare 1020 error WAF challenge page bot protection false positive"
    ),
    ("vercel_deployment_protection", "vercel"): (
        "Vercel deployment protection preview authentication gate scanner bypass"
    ),
    ("provider_blocked_scan", "cloudflare"): (
        "Cloudflare WAF scan blocked access denied challenge false positive"
    ),
    ("provider_blocked_scan", "imperva"): (
        "Imperva WAF scan blocked challenge page false positive"
    ),
    ("threat_intel_match", "cloudflare"): (
        "Cloudflare shared IP CDN GreyNoise AbuseIPDB false positive shared infrastructure"
    ),
    ("missing_csp", "cloudflare"): (
        "Cloudflare CDN content security policy header injection CSP"
    ),
    ("missing_hsts", "fastly"): (
        "Fastly CDN HSTS header injection strict transport security"
    ),
}


def normalize_provider(provider: str | None) -> str | None:
    """Return canonical provider name or None."""
    if not provider:
        return None
    return PROVIDER_ALIASES.get(provider.lower().strip())


def resolve_provider_query(
    finding_type: str,
    provider: str | None,
    symptom: str = "",
) -> str:
    """Build a knowledge-base query string for a provider + finding context."""
    canon = normalize_provider(provider)

    # Check for specialized query first
    if canon and (finding_type, canon) in SPECIALIZED_QUERIES:
        return SPECIALIZED_QUERIES[(finding_type, canon)]

    # Generic provider query
    parts: list[str] = []
    if canon and canon in PROVIDER_QUERY_MAP:
        parts.append(PROVIDER_QUERY_MAP[canon])
    elif provider:
        parts.append(provider)

    # Add symptom if given
    if symptom:
        parts.append(symptom)
    elif finding_type:
        parts.append(finding_type.replace("_", " "))

    return " ".join(parts) if parts else finding_type.replace("_", " ")


def get_provider_name(provider: str | None) -> str:
    """Return normalized display name for a provider."""
    if not provider:
        return "Unknown"
    return PROVIDER_ALIASES.get(provider.lower().strip(), provider)
