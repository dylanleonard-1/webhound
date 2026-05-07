# WebHound — scanner/webhound/wade/context_engine.py
# Classifies page URLs into security-relevant context types and returns a weight
# multiplier used by the anomaly scorer.  High-sensitivity pages (checkout, admin,
# login) produce higher anomaly scores for the same diff signal.

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Context type definitions
# ---------------------------------------------------------------------------

# Ordered: first match wins.  Patterns cover common URL conventions.
_CONTEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/admin",    re.IGNORECASE), "admin"),
    (re.compile(r"/checkout", re.IGNORECASE), "checkout"),
    (re.compile(r"/payment",  re.IGNORECASE), "checkout"),
    (re.compile(r"/pay(/|$)", re.IGNORECASE), "checkout"),
    (re.compile(r"/cart",     re.IGNORECASE), "cart"),
    (re.compile(r"/basket",   re.IGNORECASE), "cart"),
    (re.compile(r"/login",    re.IGNORECASE), "login"),
    (re.compile(r"/signin",   re.IGNORECASE), "login"),
    (re.compile(r"/sign-in",  re.IGNORECASE), "login"),
    (re.compile(r"/password", re.IGNORECASE), "login"),
    (re.compile(r"/reset",    re.IGNORECASE), "login"),
    (re.compile(r"/account",  re.IGNORECASE), "account"),
    (re.compile(r"/profile",  re.IGNORECASE), "account"),
    (re.compile(r"/dashboard",re.IGNORECASE), "account"),
    (re.compile(r"/my[-_/]",  re.IGNORECASE), "account"),
    (re.compile(r"/api/",     re.IGNORECASE), "api"),
    (re.compile(r"/graphql",  re.IGNORECASE), "api"),
]

# Weight multipliers: how much to amplify anomaly scores on each page type
CONTEXT_WEIGHTS: dict[str, float] = {
    "admin":    2.0,
    "checkout": 1.8,
    "cart":     1.4,
    "login":    1.5,
    "account":  1.4,
    "api":      1.3,
    "default":  1.0,
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
        return PageContext(url=url, context_type="default", weight=1.0)

    def weight_for(self, url: str) -> float:
        return self.classify(url).weight

    def context_for(self, url: str) -> str:
        return self.classify(url).context_type

    def known_contexts(self) -> list[str]:
        return sorted(CONTEXT_WEIGHTS.keys())
