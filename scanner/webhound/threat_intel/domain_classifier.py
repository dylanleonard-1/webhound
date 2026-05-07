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


# ---------------------------------------------------------------------------
# Static data
# ---------------------------------------------------------------------------

# CDN / infrastructure domains: always expected, no security concern.
_TRUSTED_DOMAINS: frozenset[str] = frozenset({
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
})

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
    "risky_tld":            4.0,
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
