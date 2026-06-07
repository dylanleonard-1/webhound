# WebHound — scanner/webhound/advisor/change_explainer.py
# Phase-15 Task 2/7: explain WADE changes in plain language ("a new
# third-party script appeared on your checkout page") and explain trends
# (risk increasing/decreasing/stable, recurring issues).
#
# Consumes the monitoring layer's ChangeEvent + RiskDelta shapes (or the
# raw WADE timeline records) — no new detection, just translation.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Asset → friendly noun.
_ASSET_NOUN = {
    "script": "third-party script", "form": "form",
    "api_endpoint": "API endpoint", "third_party_domain": "third-party domain",
    "iframe": "embedded frame (iframe)", "redirect": "redirect",
    "technology": "technology", "header": "security header",
    "cookie": "cookie", "page": "page", "auth_surface": "authentication surface",
}


@dataclass
class ChangeExplanation:
    headline: str
    detail: str
    confidence: str
    is_alarming: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "detail": self.detail,
            "confidence": self.confidence,
            "is_alarming": self.is_alarming,
        }


def _page_phrase(url: str | None) -> str:
    if not url:
        return ""
    low = url.lower()
    if "checkout" in low or "payment" in low:
        return " on your checkout page"
    if "login" in low or "signin" in low or "account" in low:
        return " on your login/account page"
    if "admin" in low:
        return " on your admin page"
    return ""


def explain_change(event: Any) -> ChangeExplanation:
    """Explain one ChangeEvent (or dict with asset/category/title/url/
    confidence/direction/tier)."""
    def g(k, default=""):
        if isinstance(event, dict):
            return event.get(k, default)
        return getattr(event, k, default)

    asset = g("asset", "page")
    noun = _ASSET_NOUN.get(asset, "item")
    url = g("url")
    category = g("category", "")
    direction = g("direction", "unchanged")
    confidence = g("confidence", "medium")
    tier = g("tier", "notice")
    page = _page_phrase(url)

    alarming = (category == "possible_compromise"
                or tier in ("warning", "critical"))

    if category == "possible_compromise":
        headline = f"A suspicious {noun} change was detected{page}."
        detail = ("This change matches a pattern often seen during website "
                  "tampering. It was not present (or differed) in previous "
                  "scans and is worth investigating before dismissing.")
    elif direction == "increased":
        headline = f"A new {noun} appeared{page}."
        detail = ("This was not present in previous scans. New third-party "
                  "code and forms change your site's exposure, so confirm it "
                  "was an intended change.")
    elif direction == "decreased":
        headline = f"A {noun} was removed{page}."
        detail = ("Something present in previous scans is gone. This usually "
                  "reduces exposure — confirm it was intentional.")
    else:
        headline = f"A {noun} changed{page}."
        detail = ("A difference from previous scans was recorded for your "
                  "visibility.")

    return ChangeExplanation(
        headline=headline, detail=detail,
        confidence=confidence, is_alarming=alarming)


def explain_trend(risk_delta: Any) -> ChangeExplanation:
    """Explain the risk-score movement between scans (Task 7).

    Accepts a monitoring.RiskDelta or a dict with direction / score_change
    / reasons / previous_level / current_level."""
    def g(k, default=None):
        if isinstance(risk_delta, dict):
            return risk_delta.get(k, default)
        return getattr(risk_delta, k, default)

    direction = g("direction", "unchanged")
    direction = getattr(direction, "value", direction)
    change = g("score_change", 0)
    reasons = g("reasons", []) or []
    prev = g("previous_level"); cur = g("current_level")

    reason_txt = ("; ".join(str(r) for r in reasons)
                  if reasons else "no material change")

    if direction == "increased":
        headline = f"Your risk increased ({change:+d} points)."
        detail = (f"Risk rose because: {reason_txt}. "
                  + (f"Your level moved from {prev} to {cur}. "
                     if prev != cur else "")
                  + "Review the changes driving the increase first.")
        alarming = True
    elif direction == "decreased":
        headline = f"Your risk decreased ({change:+d} points)."
        detail = (f"Risk fell because: {reason_txt}. Good progress — "
                  "keep monitoring to make sure it holds.")
        alarming = False
    else:
        headline = "Your risk is stable."
        detail = ("No meaningful change in your security posture since the "
                  "last scan. A stable site is a healthy sign.")
        alarming = False

    return ChangeExplanation(
        headline=headline, detail=detail,
        confidence="high", is_alarming=alarming)


def explain_recurring(event: Any) -> str:
    """A short note for a recurring change (Task 7)."""
    def g(k, default=None):
        if isinstance(event, dict):
            return event.get(k, default)
        return getattr(event, k, default)
    occ = g("occurrences", 1)
    title = g("title", "this change")
    if occ and occ > 1:
        return (f"'{title}' has appeared in {occ} scans — it's a recurring "
                "item, not a one-off. If it's expected, you can acknowledge "
                "it to quiet future alerts.")
    return ""
