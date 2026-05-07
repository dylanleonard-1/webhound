# WebHound — scanner/webhound/core/fp_filter.py
# False-positive confidence filter for common platform and CDN patterns.
#
# Real-world sites using well-known CDNs, analytics platforms, or popular
# frameworks (Next.js, Shopify, Squarespace) naturally exhibit patterns that
# can produce low-signal findings.  This filter reduces (but never removes)
# confidence on such findings so they don't dominate the risk score.
#
# Findings are NEVER deleted — only confidence is adjusted downward.
# Callers can inspect the original confidence via finding.confidence.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from webhound.models.finding import Finding, FindingCategory

# ---------------------------------------------------------------------------
# Known-safe CDN / analytics domains
# ---------------------------------------------------------------------------

_KNOWN_CDN_DOMAINS: frozenset[str] = frozenset({
    "googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "googlefonts.com",
    "fonts.gstatic.com",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "fastly.net",
    "akamaihd.net",
    "akamai.net",
    "bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "jquery.com",
    "code.jquery.com",
    "facebook.net",
    "fbcdn.net",
    "twitter.com",
    "twimg.com",
    "hotjar.com",
    "segment.io",
    "segment.com",
    "intercom.io",
    "intercomcdn.com",
    "shopify.com",
    "cdn.shopify.com",
    "myshopify.com",
    "squarespace.com",
    "squarespace-cdn.com",
    "vercel.app",
    "vercel-cdn.com",
    "netlify.app",
})

# ---------------------------------------------------------------------------
# Known-safe URL path patterns (regex) — e.g. framework build artifacts
# ---------------------------------------------------------------------------

_SAFE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/_next/"),          # Next.js
    re.compile(r"/__nuxt/"),         # Nuxt.js
    re.compile(r"/gatsby-"),         # Gatsby
    re.compile(r"/static/chunks/"),  # webpack code-split output
    re.compile(r"\.shopify\.com"),   # Shopify sub-domain
]

# ---------------------------------------------------------------------------
# FP rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FPRule:
    """A single false-positive suppression rule."""

    description: str
    matches: Callable[[Finding], bool]
    confidence_multiplier: float  # Applied to the original confidence (0 < x < 1)


def _matches_cdn_domain(finding: Finding) -> bool:
    """True if any evidence location references a known CDN domain."""
    for ev in finding.evidence:
        loc = ev.location.lower()
        if any(cdn in loc for cdn in _KNOWN_CDN_DOMAINS):
            return True
    # Also check content for domain names
    for ev in finding.evidence:
        content = (ev.content or "").lower()
        if any(cdn in content for cdn in _KNOWN_CDN_DOMAINS):
            return True
    return False


def _matches_safe_path(finding: Finding) -> bool:
    """True if any evidence location matches a framework build-artifact path."""
    for ev in finding.evidence:
        loc = ev.location
        if any(p.search(loc) for p in _SAFE_PATH_PATTERNS):
            return True
    return False


def _is_third_party_cdn(finding: Finding) -> bool:
    return (
        finding.category == FindingCategory.JAVASCRIPT
        and finding.scanner_engine == "third_party_domains"
        and _matches_cdn_domain(finding)
    )


def _is_technology_info(finding: Finding) -> bool:
    """Technology detection findings are informational by nature."""
    return finding.scanner_engine == "technology"


def _is_safe_framework_path(finding: Finding) -> bool:
    """Recon findings for known framework paths are expected, not exposures."""
    return (
        finding.category == FindingCategory.RECON
        and _matches_safe_path(finding)
    )


_RULES: list[_FPRule] = [
    _FPRule(
        description="Known CDN/analytics third-party domain",
        matches=_is_third_party_cdn,
        confidence_multiplier=0.4,
    ),
    _FPRule(
        description="Technology detection (informational)",
        matches=_is_technology_info,
        confidence_multiplier=0.7,
    ),
    _FPRule(
        description="Expected framework build-artifact path",
        matches=_is_safe_framework_path,
        confidence_multiplier=0.3,
    ),
]

# Minimum confidence floor — we always preserve some signal.
_MIN_CONFIDENCE: float = 0.1


# ---------------------------------------------------------------------------
# FPFilter
# ---------------------------------------------------------------------------


class FPFilter:
    """Adjust finding confidence downward for known false-positive patterns.

    Findings are never removed — only ``confidence`` is reduced.  Callers can
    still access all raw findings in ``ScanResult.findings``.

    Usage::

        filtered = FPFilter().filter(findings)
    """

    def filter(self, findings: list[Finding]) -> list[Finding]:
        """Return a new list where matching findings have reduced confidence.

        Each finding is replaced with a copy whose ``confidence`` is multiplied
        by the rule's factor (floored at ``_MIN_CONFIDENCE``).
        """
        result: list[Finding] = []
        for f in findings:
            multiplier = self._apply_rules(f)
            if multiplier < 1.0:
                new_confidence = max(_MIN_CONFIDENCE, f.confidence * multiplier)
                f = f.model_copy(update={"confidence": round(new_confidence, 4)})
            result.append(f)
        return result

    def _apply_rules(self, finding: Finding) -> float:
        """Return the product of all matching rule multipliers (<= 1.0)."""
        multiplier = 1.0
        for rule in _RULES:
            if rule.matches(finding):
                multiplier *= rule.confidence_multiplier
        return multiplier
