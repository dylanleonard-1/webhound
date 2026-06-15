# WebHound — scanner/webhound/threat_intel/domain_classifier.py
# Local domain classification: no network calls, no external API dependencies.
#
# Classifies domains into risk tiers using static allowlists, heuristics, and
# pattern matching. Designed as the authoritative source of domain risk signals
# shared across all scanner engines (JS, forms, recon, compromise).

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import tldextract

# ---------------------------------------------------------------------------
# Classification tiers
# ---------------------------------------------------------------------------


class DomainClass(str, Enum):
    """Ordered risk tiers for domain classification (lower = safer)."""

    TRUSTED = "trusted"                  # Known-good CDN / infrastructure
    COMMON_BENIGN = "common_benign"      # Legitimate service (analytics, payment)
    UNKNOWN = "unknown"                  # No risk signals; not on any list
    SUSPICIOUS = "suspicious"            # Mild signals (few hyphens, shortener, etc.)
    RISKY = "risky"                      # Strong signals (risky TLD, brand lookalike)
    MALICIOUS_INDICATOR = "malicious_indicator"  # Multiple converging signals


# Numeric severity rank (higher = more dangerous) — used for comparison.
_CLASS_RANK: dict[DomainClass, int] = {
    DomainClass.TRUSTED: 0,
    DomainClass.COMMON_BENIGN: 0,
    DomainClass.UNKNOWN: 1,
    DomainClass.SUSPICIOUS: 2,
    DomainClass.RISKY: 3,
    DomainClass.MALICIOUS_INDICATOR: 4,
}


@dataclass(frozen=True)
class DomainClassification:
    """Result of a local domain classification."""

    domain: str                             # Normalised input domain
    classification: DomainClass
    confidence: float                       # [0.0, 1.0]
    score: float                            # 0.0–10.0 (10 = highest risk)
    signals: list[str]                      # Human-readable contributing signals
    registerable_domain: str | None         # e.g. "evil.com" from "sub.evil.com"
    tld: str | None                         # Effective TLD (e.g. "co.uk")
    is_punycode: bool                       # Any label starts with "xn--"
    is_url_shortener: bool                  # Registered domain is a known shortener
    # Functional category — WHAT the vendor does (analytics/ads/cdn/
    # payment/chat/identity/marketing/hosting/commerce/social/media/
    # unknown). Orthogonal to the risk tier above: a payment vendor is
    # "payment" whether or not the domain itself looks risky. Used by
    # reporting to present known services as inventory, not threats.
    vendor_category: str = "unknown"


# ---------------------------------------------------------------------------
# Static data
# ---------------------------------------------------------------------------

# CDN / infrastructure / platform domains: always expected, no security
# concern. Adding a vendor here means any signal (risky TLD, lookalike, etc.)
# is overruled by the explicit allowlist — use sparingly + only for vendors
# with strong identity verification.
_TRUSTED_DOMAINS: frozenset[str] = frozenset({
    # CDNs / infra
    "googleapis.com", "gstatic.com", "googletagmanager.com",
    "cloudflare.com", "cloudflare.net",
    "jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
    "jquery.com", "jquery.org",
    "cloudfront.net",
    "fastly.net", "fastly.com",
    "akamaized.net", "akamai.com", "akamaihd.net",
    "github.io", "github.com", "githubusercontent.com",
    "typekit.net",
    "vimeocdn.com",
    "ytimg.com",
    "twimg.com",
    # Platform-as-a-service hosts. These end in TLDs that the heuristic
    # treats as abuse-prone (.link, .app, .dev) — without explicit
    # allowlisting they were getting flagged HIGH on TLD-alone, which is the
    # specific false positive the user surfaced for vercel.link.
    "vercel.app", "vercel.com", "vercel.link", "now.sh",
    "netlify.app", "netlify.com",
    "railway.app",
    "fly.dev", "fly.io",
    "render.com",
    "pages.dev",            # Cloudflare Pages
    "workers.dev",          # Cloudflare Workers
    "azurestaticapps.net",
    "azurewebsites.net",
    "herokuapp.com",
    "supabase.co", "supabase.in",
    "firebaseapp.com", "web.app",
    "amplifyapp.com",
    "appspot.com",          # Google App Engine
    "run.app",              # Google Cloud Run
    "sentry.io", "sentry-cdn.com",
    "vercel-insights.com",
    # Additional shared hosting / PaaS platforms — subdomains of these are
    # expected end-user deployments, not attacker-controlled. Without explicit
    # listing, a subdomain containing a suspicious keyword or on a "link/dev/app"
    # TLD could accumulate enough heuristic signals to trigger a false-positive
    # RISKY or MALICIOUS_INDICATOR verdict.
    "digitalocean.app", "digitaloceanspaces.com", "ondigitalocean.app",
    "wpengine.com",
    "kinsta.com",
    "pantheon.io",
    "platform.sh",
    "cloudways.com",
    "a2hosting.com", "a2cdn.net",
    "siteground.net", "sgcpanel.com",
    "bluehost.com",
    "dreamhost.com",
    "godaddy.com",
    "hostgator.com",
    "namecheap.com",
    "ionos.com",
    "hetzner.com",
    "linode.com", "linodeobjects.com",
    "vultr.com",
    "replit.com", "repl.co",
    "glitch.me", "glitch.com",
    "stackblitz.io",
    "codesandbox.io",
    "netlify.live",
})

# Legitimate third-party services that handle user data — expected but worth noting.
_COMMON_BENIGN_DOMAINS: frozenset[str] = frozenset({
    "google.com", "google-analytics.com", "doubleclick.net",
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "t.co",
    "instagram.com",
    "linkedin.com", "licdn.com",
    "youtube.com",
    "vimeo.com",
    "stripe.com", "stripe.network",
    "paypal.com", "paypalobjects.com",
    "braintreegateway.com",
    "amazonaws.com",
    "azure.com", "azurewebsites.net",
    "hotjar.com",
    "intercom.io", "intercomcdn.com",
    "disqus.com", "disquscdn.com",
    "addthis.com",
    "adobe.com", "adobedtm.com",
    # Phase-6C additions — vendors the browser pass routinely observes
    # at runtime. Listing them here keeps heuristics (keyword / TLD /
    # hyphen rules) from turning household services into findings.
    "shopify.com", "myshopify.com", "shopifycdn.com", "shopifysvc.com",
    "wix.com", "wixstatic.com", "wixsite.com", "parastorage.com",
    "webflow.com", "webflow.io", "website-files.com",
    "squarespace.com", "squarespace-cdn.com",
    "bigcommerce.com",
    "tiktok.com", "tiktokcdn.com", "byteoversea.com",
    "klaviyo.com",
    "hubspot.com", "hs-scripts.com", "hsforms.com", "hubapi.com",
    "zendesk.com", "zdassets.com",
    "mailchimp.com", "list-manage.com", "chimpstatic.com",
    "segment.com", "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "clarity.ms",
    "drift.com", "driftt.com",
    "crisp.chat",
    "tawk.to",
    "auth0.com",
    "okta.com", "oktacdn.com",
    "clerk.com", "clerk.dev",
    "microsoftonline.com",
    "klarna.com", "afterpay.com", "squareup.com", "adyen.com",
    "criteo.com", "taboola.com", "outbrain.com",
    "googlesyndication.com", "googleadservices.com",
})

# ---------------------------------------------------------------------------
# Functional vendor categories (Phase-6C).
# WHAT a vendor does, keyed by registrable domain. Orthogonal to risk:
# reporting uses this to file known services under inventory instead of
# presenting "site uses Stripe" as a security finding.
# ---------------------------------------------------------------------------

_VENDOR_CATEGORIES: dict[str, str] = {
    # analytics / telemetry
    "google-analytics.com": "analytics", "googletagmanager.com": "analytics",
    "hotjar.com": "analytics", "mixpanel.com": "analytics",
    "segment.com": "analytics", "segment.io": "analytics",
    "amplitude.com": "analytics", "clarity.ms": "analytics",
    "plausible.io": "analytics", "sentry.io": "analytics",
    "sentry-cdn.com": "analytics", "vercel-insights.com": "analytics",
    "newrelic.com": "analytics", "nr-data.net": "analytics",
    "datadoghq.com": "analytics",
    # ads
    "doubleclick.net": "ads", "googlesyndication.com": "ads",
    "googleadservices.com": "ads", "adnxs.com": "ads",
    "criteo.com": "ads", "taboola.com": "ads", "outbrain.com": "ads",
    "facebook.net": "ads", "tiktokcdn.com": "ads",
    # cdn / infra
    "cloudflare.com": "cdn", "cloudflare.net": "cdn",
    "jsdelivr.net": "cdn", "unpkg.com": "cdn",
    "bootstrapcdn.com": "cdn", "cloudfront.net": "cdn",
    "fastly.net": "cdn", "fastly.com": "cdn",
    "akamaized.net": "cdn", "akamai.com": "cdn", "akamaihd.net": "cdn",
    "gstatic.com": "cdn", "googleapis.com": "cdn",
    "typekit.net": "cdn", "fbcdn.net": "cdn", "licdn.com": "cdn",
    "twimg.com": "cdn", "ytimg.com": "cdn", "vimeocdn.com": "cdn",
    "jquery.com": "cdn", "jquery.org": "cdn",
    "shopifycdn.com": "cdn", "squarespace-cdn.com": "cdn",
    "website-files.com": "cdn", "wixstatic.com": "cdn",
    "parastorage.com": "cdn", "chimpstatic.com": "cdn",
    "intercomcdn.com": "cdn", "zdassets.com": "cdn",
    "oktacdn.com": "cdn", "disquscdn.com": "cdn",
    "paypalobjects.com": "cdn",
    # payment
    "stripe.com": "payment", "stripe.network": "payment",
    "paypal.com": "payment", "braintreegateway.com": "payment",
    "klarna.com": "payment", "afterpay.com": "payment",
    "squareup.com": "payment", "adyen.com": "payment",
    # chat / support
    "intercom.io": "chat", "zendesk.com": "chat",
    "drift.com": "chat", "driftt.com": "chat",
    "crisp.chat": "chat", "tawk.to": "chat",
    "livechatinc.com": "chat",
    # identity / auth
    "auth0.com": "identity", "okta.com": "identity",
    "clerk.com": "identity", "clerk.dev": "identity",
    "microsoftonline.com": "identity",
    # marketing / CRM / email
    "klaviyo.com": "marketing", "hubspot.com": "marketing",
    "hs-scripts.com": "marketing", "hsforms.com": "marketing",
    "hubapi.com": "marketing",
    "mailchimp.com": "marketing", "list-manage.com": "marketing",
    "marketo.com": "marketing", "braze.com": "marketing",
    "addthis.com": "marketing", "adobedtm.com": "marketing",
    # hosting / platform
    "vercel.app": "hosting", "vercel.com": "hosting",
    "netlify.app": "hosting", "netlify.com": "hosting",
    "railway.app": "hosting", "fly.dev": "hosting", "fly.io": "hosting",
    "render.com": "hosting", "herokuapp.com": "hosting",
    "pages.dev": "hosting", "workers.dev": "hosting",
    "github.io": "hosting", "amazonaws.com": "hosting",
    "azurewebsites.net": "hosting", "azurestaticapps.net": "hosting",
    "appspot.com": "hosting", "run.app": "hosting",
    "supabase.co": "hosting", "supabase.in": "hosting",
    "firebaseapp.com": "hosting", "web.app": "hosting",
    "amplifyapp.com": "hosting",
    # commerce platforms
    "shopify.com": "commerce", "myshopify.com": "commerce",
    "shopifysvc.com": "commerce",
    "wix.com": "commerce", "wixsite.com": "commerce",
    "webflow.com": "commerce", "webflow.io": "commerce",
    "squarespace.com": "commerce", "bigcommerce.com": "commerce",
    "woocommerce.com": "commerce",
    # social / embeds
    "facebook.com": "social", "instagram.com": "social",
    "twitter.com": "social", "linkedin.com": "social",
    "tiktok.com": "social", "byteoversea.com": "social",
    "disqus.com": "social",
    # media embeds
    "youtube.com": "media", "vimeo.com": "media",
}


def vendor_category(domain: str) -> str:
    """Functional category for *domain* ("unknown" when unrecognised).
    Matches on the registrable domain so cdn.shopify.com → shopify.com."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return "unknown"
    registered = _registerable_domain(d)
    return _VENDOR_CATEGORIES.get(registered or d,
                                  _VENDOR_CATEGORIES.get(d, "unknown"))

# TLDs with historically high abuse / spam rates.
_RISKY_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",          # Freenom free TLDs
    "xyz", "top", "win", "date", "review", "racing", "stream",
    "download", "click", "link",
    "cc", "pw", "su",
    "work", "icu", "buzz", "live", "space",
    "online", "site", "website",
})

# Registered domains of well-known URL shortening services.
_URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "dlvr.it", "ht.ly", "j.mp", "short.io", "tiny.cc", "is.gd",
    "v.gd", "qr.ae", "adf.ly", "bc.vc", "rb.gy", "shorte.st",
    "cutt.ly", "shorturl.at", "clicky.me",
})

# Brand names whose appearance in an unrecognised domain indicates potential lookalike.
_BRANDS: frozenset[str] = frozenset({
    "paypal", "google", "amazon", "apple", "microsoft", "facebook",
    "instagram", "netflix", "twitter", "linkedin", "ebay", "walmart",
    "chase", "wellsfargo", "bankofamerica", "citibank", "barclays",
    "coinbase", "binance", "kraken", "metamask",
    "dropbox", "onedrive", "icloud", "gmail",
})

# Keywords in domain labels that increase suspicion (non-brand-specific).
_SUSPICIOUS_KW_RE = re.compile(
    r"\b(?:login|signin|sign-in|secure|security|update|verify|"
    r"verification|account|banking|wallet|crypto|bitcoin|"
    r"support|helpdesk|unlock|confirm|reset|recovery|"
    r"invoice|payment|checkout|billing)\b",
    re.I,
)

# ---------------------------------------------------------------------------
# Scoring weights for each signal type.
# These sum to a raw score; final score is capped at 10.0.
# ---------------------------------------------------------------------------

_SIGNAL_WEIGHTS: dict[str, float] = {
    # `risky_tld` alone shouldn't push a domain into RISKY tier — the TLD
    # heuristic is a weak signal that flagged legitimate platform domains
    # (vercel.link, *.dev) before the explicit allowlist was added.
    # Lowered 4.0 → 2.5 so it now needs a second corroborating signal
    # (suspicious_keyword, brand_lookalike, random_looking, …) to cross
    # the 4.0 RISKY threshold.
    "risky_tld":            2.5,
    "brand_lookalike":      4.5,
    "url_shortener":        3.0,
    "punycode":             3.0,
    "random_looking":       3.5,
    "excessive_hyphens":    2.5,
    "very_long_domain":     1.5,
    "suspicious_keyword":   2.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registerable_domain(hostname: str) -> str | None:
    """Return 'domain.suffix' from a hostname, or None if unparseable."""
    if not hostname:
        return None
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _effective_tld(hostname: str) -> str | None:
    """Return the effective TLD (suffix) of a hostname."""
    ext = tldextract.extract(hostname)
    return ext.suffix.lower() if ext.suffix else None


def _is_punycode(domain: str) -> bool:
    """True if any label in the domain begins with the ACE prefix 'xn--'."""
    labels = domain.rstrip(".").lower().split(".")
    return any(label.startswith("xn--") for label in labels)


def _looks_random(label: str) -> bool:
    """True when a domain label looks DGA/machine-generated.

    Uses two complementary heuristics:
    - Very low vowel ratio (< 12 %)
    - High Shannon entropy (> 3.8 bits/char) for labels of ≥ 8 characters
    """
    if len(label) < 8:
        return False
    vowels = "aeiou"
    vowel_ratio = sum(1 for c in label.lower() if c in vowels) / len(label)
    if vowel_ratio < 0.12:
        return True
    counts = Counter(label.lower())
    n = len(label)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy > 3.8


def _brand_lookalike_signal(domain: str, registered: str | None) -> str | None:
    """Return a signal string if the domain appears to impersonate a known brand."""
    if registered and registered in (_TRUSTED_DOMAINS | _COMMON_BENIGN_DOMAINS):
        return None
    # Strip separators and check the entire hostname (catches sub.brand.evil.com too)
    flattened = domain.lower().replace("-", "").replace("_", "").replace(".", "")
    for brand in _BRANDS:
        if brand in flattened:
            return f"potential brand lookalike: '{brand}' in domain"
    return None


def _classify_from_score(score: float, signal_keys: set[str]) -> DomainClass:
    """Map a numeric score (and optional signal keys) to a DomainClass."""
    if score == 0.0:
        return DomainClass.UNKNOWN
    if score >= 8.0:
        return DomainClass.MALICIOUS_INDICATOR
    if score >= 4.0:
        return DomainClass.RISKY
    return DomainClass.SUSPICIOUS


def _compute_confidence(signals: list[str], score: float) -> float:
    base = 0.50
    signal_boost = min(0.05 * len(signals), 0.25)
    score_boost = min(score / 40.0, 0.20)
    return round(min(base + signal_boost + score_boost, 0.95), 2)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class DomainClassifier:
    """Local, offline domain risk classifier.

    All classification is performed in-memory using static lists and heuristics.
    No DNS lookups, no HTTP fetches, no external API calls.

    Usage::

        clf = DomainClassifier()
        result = clf.classify("evil-paypal.tk")
        print(result.classification)  # DomainClass.MALICIOUS_INDICATOR
    """

    # Expose the static data sets so engines can import them from here
    # rather than duplicating them.
    trusted_domains: frozenset[str] = _TRUSTED_DOMAINS
    common_benign_domains: frozenset[str] = _COMMON_BENIGN_DOMAINS
    risky_tlds: frozenset[str] = _RISKY_TLDS
    url_shorteners: frozenset[str] = _URL_SHORTENERS

    def classify(self, domain: str) -> DomainClassification:
        """Classify a single domain or hostname."""
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            return self._empty(domain)

        registered = _registerable_domain(domain)
        tld = _effective_tld(domain)
        is_punycode = _is_punycode(domain)
        is_shortener = bool(registered and registered in _URL_SHORTENERS)

        # ------------------------------------------------------------------
        # Fast-path: known-good lists (no further analysis needed)
        # ------------------------------------------------------------------
        if registered and registered in _TRUSTED_DOMAINS:
            return DomainClassification(
                domain=domain,
                classification=DomainClass.TRUSTED,
                confidence=0.95,
                score=0.0,
                signals=["trusted CDN/infrastructure provider"],
                registerable_domain=registered,
                tld=tld,
                is_punycode=is_punycode,
                is_url_shortener=False,
                vendor_category=vendor_category(domain),
            )

        if registered and registered in _COMMON_BENIGN_DOMAINS:
            return DomainClassification(
                domain=domain,
                classification=DomainClass.COMMON_BENIGN,
                confidence=0.90,
                score=0.5,
                signals=["known legitimate third-party service"],
                registerable_domain=registered,
                tld=tld,
                is_punycode=is_punycode,
                is_url_shortener=False,
                vendor_category=vendor_category(domain),
            )

        # ------------------------------------------------------------------
        # Collect risk signals
        # ------------------------------------------------------------------
        signal_keys: set[str] = set()
        signals: list[str] = []

        def _add(key: str, description: str) -> None:
            signal_keys.add(key)
            signals.append(description)

        if is_punycode:
            _add("punycode", "punycode/IDN domain — possible homoglyph attack")

        if is_shortener:
            _add("url_shortener", f"URL shortener service ({registered})")

        if tld and tld in _RISKY_TLDS:
            _add("risky_tld", f"high-abuse TLD (.{tld})")

        ext = tldextract.extract(domain)
        label = ext.domain.lower()

        if label and label.count("-") >= 3:
            _add("excessive_hyphens", f"excessive hyphens in domain label ({label.count('-')})")

        if label and _looks_random(label):
            _add("random_looking", "domain label appears machine-generated / DGA-like")

        if len(domain) > 50:
            _add("very_long_domain", f"unusually long domain ({len(domain)} chars)")

        brand_signal = _brand_lookalike_signal(domain, registered)
        if brand_signal:
            _add("brand_lookalike", brand_signal)

        if label and _SUSPICIOUS_KW_RE.search(label.replace("-", " ")):
            _add("suspicious_keyword", "suspicious keyword in domain label")

        # ------------------------------------------------------------------
        # Score and classify
        # ------------------------------------------------------------------
        raw_score = sum(_SIGNAL_WEIGHTS.get(k, 1.0) for k in signal_keys)
        score = round(min(raw_score, 10.0), 2)
        classification = _classify_from_score(score, signal_keys)
        confidence = _compute_confidence(signals, score) if signals else 0.55

        return DomainClassification(
            domain=domain,
            classification=classification,
            confidence=confidence,
            score=score,
            signals=signals,
            registerable_domain=registered,
            tld=tld,
            is_punycode=is_punycode,
            is_url_shortener=is_shortener,
            vendor_category=vendor_category(domain),
        )

    @staticmethod
    def _empty(domain: str) -> DomainClassification:
        return DomainClassification(
            domain=domain,
            classification=DomainClass.UNKNOWN,
            confidence=0.0,
            score=0.0,
            signals=[],
            registerable_domain=None,
            tld=None,
            is_punycode=False,
            is_url_shortener=False,
        )
