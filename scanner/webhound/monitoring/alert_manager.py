# WebHound — scanner/webhound/monitoring/alert_manager.py
# Phase-11 Tasks 3,4,6,7: turn tracked changes + security stories + the
# risk delta into customer-facing Alerts.
#
# An Alert is the thing a customer reads: a tier, a category, a human
# story, and an action. The manager:
#   * assigns the alert tier from the change/story (Task 3)
#   * suppresses noise — recurring already-seen changes, expected
#     deployments, content/image/marketing edits, known vendor/framework
#     updates (Task 4)
#   * writes a plain-language story (Task 7)
# Pure — consumes monitoring + scan-metadata objects, no network.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.monitoring.change_history import (
    AlertTier,
    ChangeCategory,
    ChangeEvent,
    ChangeHistory,
    RiskDirection,
)
from webhound.monitoring.risk_delta import RiskDelta

# Categories whose changes are inherently low-noise / expected.
_QUIET_CATEGORIES = {
    ChangeCategory.CONTENT.value,
}

# WADE change_type / story signals that mean "expected, suppress".
_EXPECTED_MARKERS = (
    "expected_deployment", "normal_content_update",
    "framework_normal",
)


@dataclass
class Alert:
    """One customer-facing alert."""

    tier: AlertTier
    category: str
    title: str
    story: str
    recommended_action: str
    confidence: str = "medium"
    affected_areas: list[str] = field(default_factory=list)
    change_keys: list[str] = field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value if isinstance(self.tier, AlertTier)
            else self.tier,
            "category": self.category,
            "title": self.title,
            "story": self.story,
            "recommended_action": self.recommended_action,
            "confidence": self.confidence,
            "affected_areas": list(self.affected_areas),
            "change_keys": list(self.change_keys),
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


# ---------------------------------------------------------------------------
# Suppression (Task 4)
# ---------------------------------------------------------------------------


def _suppress_reason(event: ChangeEvent, *, seen_before: bool) -> str | None:
    """Return a suppression reason, or None if the change should alert."""
    # Compromise indicators are NEVER suppressed.
    if event.category == ChangeCategory.POSSIBLE_COMPROMISE.value:
        return None
    # Expected/normal markers in the detail or already framework-normal.
    detail = (event.detail or "").lower()
    if any(m in detail for m in _EXPECTED_MARKERS):
        return "expected/normal change"
    # Pure content churn is noise.
    if event.category in _QUIET_CATEGORIES and \
            event.tier == AlertTier.INFORMATIONAL.value:
        return "content change"
    # A recurring, already-acknowledged change shouldn't re-alert each
    # scan (anti-spam) — unless it's high tier.
    if seen_before and event.is_recurring and \
            AlertTier(event.tier).rank < AlertTier.WARNING.rank:
        return "recurring change already reported"
    return None


# ---------------------------------------------------------------------------
# Tier assignment (Task 3)
# ---------------------------------------------------------------------------


def _event_tier(event: ChangeEvent) -> AlertTier:
    """Final tier for a change event — escalate compromise + risk-up."""
    base = AlertTier(event.tier) if event.tier in {
        t.value for t in AlertTier} else AlertTier.NOTICE
    if event.category == ChangeCategory.POSSIBLE_COMPROMISE.value:
        # A possible-compromise change is at least a Warning; with
        # confirmed confidence it's Critical.
        if event.confidence == "confirmed":
            return AlertTier.CRITICAL
        return max(base, AlertTier.WARNING, key=lambda t: t.rank)
    # Security regressions that raised risk are at least Review.
    if (event.direction == RiskDirection.INCREASED.value
            and event.category == ChangeCategory.SECURITY.value):
        return max(base, AlertTier.REVIEW, key=lambda t: t.rank)
    return base


def _story_for(event: ChangeEvent) -> tuple[str, str]:
    """(story, action) plain-language pair (Task 7)."""
    where = f" on {event.url}" if event.url else ""
    if event.category == ChangeCategory.POSSIBLE_COMPROMISE.value:
        return (
            f"WebHound detected a change that matches a compromise "
            f"pattern{where}: {event.title}. Indicators like this commonly "
            "appear together when a site is tampered with.",
            "Investigate immediately — compare against your known-good "
            "deployment and review recent changes.",
        )
    if event.category == ChangeCategory.PAYMENT.value:
        return (
            f"A change was detected on your payment surface{where}: "
            f"{event.title}.",
            "Confirm this matches an intended change to your payment setup.",
        )
    if event.category == ChangeCategory.AUTHENTICATION.value:
        return (
            f"A change was detected on an authentication surface{where}: "
            f"{event.title}.",
            "Verify this corresponds to an intended auth/login change.",
        )
    if event.category == ChangeCategory.VENDOR.value:
        return (
            f"A third-party service change was detected{where}: "
            f"{event.title}.",
            "Confirm this vendor was intentionally added or updated.",
        )
    if event.category == ChangeCategory.SECURITY.value:
        verb = ("weakened" if event.direction == RiskDirection.INCREASED.value
                else "changed")
        return (
            f"A security-relevant setting {verb}{where}: {event.title}.",
            "Review recent deployments and restore protections if this "
            "was unintended.",
        )
    return (
        f"A change was detected{where}: {event.title}.",
        "Review to confirm this change was expected.",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_alerts(
    new_events: list[ChangeEvent],
    *,
    history: ChangeHistory | None = None,
    risk_delta: RiskDelta | None = None,
    security_stories: list[dict[str, Any]] | None = None,
) -> list[Alert]:
    """Build alerts from this scan's NEW/updated change events, plus an
    optional risk-delta summary alert and story-derived alerts.

    ``history`` lets the manager know which changes were seen before
    (for anti-spam suppression)."""
    alerts: list[Alert] = []
    prior_keys = set((history.records if history else {}).keys())

    for event in new_events:
        seen_before = event.change_key in prior_keys and event.is_recurring
        reason = _suppress_reason(event, seen_before=seen_before)
        tier = _event_tier(event)
        story, action = _story_for(event)
        alerts.append(Alert(
            tier=tier,
            category=event.category,
            title=event.title,
            story=story,
            recommended_action=action,
            confidence=event.confidence,
            affected_areas=[event.url] if event.url else [],
            change_keys=[event.change_key],
            suppressed=reason is not None,
            suppression_reason=reason,
        ))

    # Risk-delta summary alert (Task 5 surfaced to the customer).
    if risk_delta is not None and \
            risk_delta.direction == RiskDirection.INCREASED:
        tier = (AlertTier.WARNING if risk_delta.level_changed
                else AlertTier.REVIEW)
        alerts.append(Alert(
            tier=tier,
            category=ChangeCategory.SECURITY.value,
            title=(f"Risk score increased "
                   f"{risk_delta.previous_score}→{risk_delta.current_score}"),
            story=("Your site's risk score rose this scan. "
                   + "; ".join(risk_delta.reasons)),
            recommended_action="Review the changes driving the increase.",
            confidence="high",
        ))

    # Story-derived alerts: surface high-confidence, non-inventory
    # security stories as their own alert (Task 7).
    for s in security_stories or []:
        if s.get("is_inventory"):
            continue
        conf = str(s.get("confidence", "medium"))
        if conf not in ("confirmed", "high"):
            continue
        sev = str(s.get("severity", "info"))
        tier = _severity_to_tier(sev)
        if tier.rank < AlertTier.REVIEW.rank:
            continue
        alerts.append(Alert(
            tier=tier,
            category=_story_category(s.get("correlation_type", "")),
            title=s.get("title", "Security story"),
            story=s.get("narrative", ""),
            recommended_action=s.get("recommendation", "Review."),
            confidence=conf,
            affected_areas=list(s.get("affected_areas") or []),
        ))

    return alerts


def _severity_to_tier(severity: str) -> AlertTier:
    return {
        "critical": AlertTier.CRITICAL,
        "high": AlertTier.WARNING,
        "medium": AlertTier.REVIEW,
        "low": AlertTier.NOTICE,
        "info": AlertTier.INFORMATIONAL,
    }.get(severity, AlertTier.NOTICE)


def _story_category(correlation_type: str) -> str:
    return {
        "possible_compromise": ChangeCategory.POSSIBLE_COMPROMISE.value,
        "supply_chain_risk": ChangeCategory.VENDOR.value,
        "payment_surface": ChangeCategory.PAYMENT.value,
        "auth_surface": ChangeCategory.AUTHENTICATION.value,
        "admin_exposure": ChangeCategory.AUTHENTICATION.value,
        "api_exposure": ChangeCategory.TECHNOLOGY.value,
        "website_modification": ChangeCategory.SECURITY.value,
        "header_hardening": ChangeCategory.SECURITY.value,
        "cookie_hardening": ChangeCategory.SECURITY.value,
    }.get(correlation_type, ChangeCategory.SECURITY.value)


def active_alerts(alerts: list[Alert]) -> list[Alert]:
    return [a for a in alerts if not a.suppressed]
