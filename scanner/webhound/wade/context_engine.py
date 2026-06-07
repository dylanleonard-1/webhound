# WebHound — scanner/webhound/wade/context_engine.py
# Classifies page URLs into security-relevant context types and returns a weight
# multiplier used by the anomaly scorer.  High-sensitivity pages (checkout, admin,
# login) produce higher anomaly scores for the same diff signal.

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Context type definitions
# ---------------------------------------------------------------------------

# Ordered: first match wins.  Patterns cover common URL conventions.
# Sensitive contexts (admin/checkout/login/account) are matched before
# the softer ones (contact) so a /account/contact page reads as account.
_CONTEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/admin",    re.IGNORECASE), "admin"),
    (re.compile(r"/wp-admin", re.IGNORECASE), "admin"),
    (re.compile(r"/checkout", re.IGNORECASE), "checkout"),
    (re.compile(r"/payment",  re.IGNORECASE), "checkout"),
    (re.compile(r"/pay(/|$)", re.IGNORECASE), "checkout"),
    (re.compile(r"/cart",     re.IGNORECASE), "cart"),
    (re.compile(r"/basket",   re.IGNORECASE), "cart"),
    (re.compile(r"/login",    re.IGNORECASE), "login"),
    (re.compile(r"/signin",   re.IGNORECASE), "login"),
    (re.compile(r"/sign-in",  re.IGNORECASE), "login"),
    (re.compile(r"/sign-up",  re.IGNORECASE), "login"),
    (re.compile(r"/register", re.IGNORECASE), "login"),
    (re.compile(r"/auth",     re.IGNORECASE), "login"),
    (re.compile(r"/oauth",    re.IGNORECASE), "login"),
    (re.compile(r"/sso",      re.IGNORECASE), "login"),
    (re.compile(r"/password", re.IGNORECASE), "login"),
    (re.compile(r"/reset",    re.IGNORECASE), "login"),
    (re.compile(r"/account",  re.IGNORECASE), "account"),
    (re.compile(r"/profile",  re.IGNORECASE), "account"),
    (re.compile(r"/dashboard",re.IGNORECASE), "account"),
    (re.compile(r"/settings", re.IGNORECASE), "account"),
    (re.compile(r"/my[-_/]",  re.IGNORECASE), "account"),
    (re.compile(r"/api/",     re.IGNORECASE), "api"),
    (re.compile(r"/graphql",  re.IGNORECASE), "api"),
    (re.compile(r"/contact",  re.IGNORECASE), "contact"),
    (re.compile(r"/support",  re.IGNORECASE), "contact"),
]

# Weight multipliers: how much to amplify anomaly scores on each page type.
# The homepage sits *below* default (1.0): a new script there is far more
# likely to be a marketing/analytics addition than an attack, so the same
# diff signal should read calmer than it would on a login or checkout page.
CONTEXT_WEIGHTS: dict[str, float] = {
    "admin":    2.0,
    "checkout": 1.8,
    "login":    1.5,
    "cart":     1.4,
    "account":  1.4,
    "api":      1.3,
    "contact":  1.1,
    "default":  1.0,
    "homepage": 0.8,
}


@dataclass
class PageContext:
    """Context type and weight multiplier for one URL."""

    url: str
    context_type: str
    weight: float


class ContextEngine:
    """Classify a URL into a security context and return its weight multiplier."""

    def classify(self, url: str) -> PageContext:
        for pattern, ctx in _CONTEXT_PATTERNS:
            if pattern.search(url):
                return PageContext(
                    url=url,
                    context_type=ctx,
                    weight=CONTEXT_WEIGHTS.get(ctx, 1.0),
                )
        if _is_homepage(url):
            return PageContext(
                url=url, context_type="homepage",
                weight=CONTEXT_WEIGHTS["homepage"],
            )
        return PageContext(url=url, context_type="default", weight=1.0)

    def weight_for(self, url: str) -> float:
        return self.classify(url).weight

    def context_for(self, url: str) -> str:
        return self.classify(url).context_type

    def known_contexts(self) -> list[str]:
        return sorted(CONTEXT_WEIGHTS.keys())


def _is_homepage(url: str) -> bool:
    """True when *url* points at a site root (no meaningful path)."""
    try:
        path = urlparse(url).path or "/"
    except Exception:  # noqa: BLE001
        return False
    return path in ("", "/", "/index.html", "/index.htm", "/index.php", "/home")
