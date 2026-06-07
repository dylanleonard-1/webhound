# WebHound — tests/test_alert_manager.py
# Phase-11 Tasks 3,4,7,8,9: alert tiers, suppression, stories, policies.

from __future__ import annotations

from webhound.monitoring.alert_manager import (
    Alert,
    active_alerts,
    build_alerts,
)
from webhound.monitoring.change_history import (
    AlertTier,
    ChangeCategory,
    ChangeEvent,
    ChangeHistory,
    RiskDirection,
    TrackedAsset,
)
from webhound.monitoring.notification_policy import (
    MonitoringMode,
    NotificationFrequency,
    NotificationPolicy,
    plan_delivery,
)
from webhound.monitoring.risk_delta import compute_risk_delta


def _ev(key="k", category=ChangeCategory.VENDOR, tier=AlertTier.NOTICE,
        direction=RiskDirection.UNCHANGED, confidence="medium",
        detail="", occurrences=1, url="https://t.test/") -> ChangeEvent:
    return ChangeEvent(
        change_key=key, asset=TrackedAsset.SCRIPT.value,
        category=category.value, tier=tier.value, direction=direction.value,
        title="Change", detail=detail, url=url, confidence=confidence,
        occurrences=occurrences)


# ---------------------------------------------------------------------------
# Tier assignment (Task 3)
# ---------------------------------------------------------------------------


def test_analytics_vendor_is_low_tier() -> None:
    alerts = build_alerts([_ev(category=ChangeCategory.VENDOR,
                               tier=AlertTier.NOTICE)])
    assert alerts[0].tier == AlertTier.NOTICE


def test_possible_compromise_escalates_to_warning_or_critical() -> None:
    warn = build_alerts([_ev(category=ChangeCategory.POSSIBLE_COMPROMISE,
                             tier=AlertTier.REVIEW, confidence="high")])
    assert warn[0].tier == AlertTier.WARNING
    crit = build_alerts([_ev(category=ChangeCategory.POSSIBLE_COMPROMISE,
                             tier=AlertTier.REVIEW, confidence="confirmed")])
    assert crit[0].tier == AlertTier.CRITICAL


def test_security_regression_at_least_review() -> None:
    a = build_alerts([_ev(category=ChangeCategory.SECURITY,
                          direction=RiskDirection.INCREASED,
                          tier=AlertTier.NOTICE)])
    assert a[0].tier.rank >= AlertTier.REVIEW.rank


# ---------------------------------------------------------------------------
# Suppression (Task 4)
# ---------------------------------------------------------------------------


def test_expected_deployment_suppressed() -> None:
    a = build_alerts([_ev(detail="expected_deployment marker")])
    assert a[0].suppressed
    assert "expected" in a[0].suppression_reason


def test_recurring_low_change_suppressed_when_seen_before() -> None:
    hist = ChangeHistory()
    hist.records["k"] = _ev("k", occurrences=3)
    a = build_alerts([_ev("k", occurrences=3, tier=AlertTier.NOTICE)],
                     history=hist)
    assert a[0].suppressed
    assert "recurring" in a[0].suppression_reason


def test_compromise_never_suppressed() -> None:
    hist = ChangeHistory()
    hist.records["k"] = _ev("k", category=ChangeCategory.POSSIBLE_COMPROMISE,
                            occurrences=5)
    a = build_alerts([_ev("k", category=ChangeCategory.POSSIBLE_COMPROMISE,
                          occurrences=5, detail="expected_deployment")],
                     history=hist)
    assert a[0].suppressed is False


def test_active_alerts_filters_suppressed() -> None:
    alerts = build_alerts([
        _ev("a", detail="expected_deployment"),
        _ev("b", category=ChangeCategory.POSSIBLE_COMPROMISE,
            confidence="high"),
    ])
    assert len(active_alerts(alerts)) == 1


# ---------------------------------------------------------------------------
# Stories + risk delta surfaced (Task 5/7)
# ---------------------------------------------------------------------------


def test_risk_increase_creates_alert() -> None:
    prev = {"risk_score": 10, "risk_level": "safe",
            "risk_breakdown": {"type_counts": {}}}
    cur = {"risk_score": 50, "risk_level": "medium",
           "risk_breakdown": {"type_counts": {"confirmed_risk": 1}}}
    delta = compute_risk_delta(prev, cur)
    alerts = build_alerts([], risk_delta=delta)
    assert any("Risk score increased" in a.title for a in alerts)
    assert alerts[0].tier == AlertTier.WARNING  # level changed


def test_high_confidence_story_becomes_alert() -> None:
    stories = [{
        "correlation_type": "possible_compromise", "confidence": "high",
        "severity": "high", "title": "Possible Website Compromise",
        "narrative": "Multiple indicators...", "recommendation": "Investigate.",
        "affected_areas": ["/checkout"], "is_inventory": False,
    }]
    alerts = build_alerts([], security_stories=stories)
    story_alert = next(a for a in alerts
                       if a.title == "Possible Website Compromise")
    assert story_alert.tier == AlertTier.WARNING
    assert story_alert.category == "possible_compromise"


def test_inventory_story_not_alerted() -> None:
    stories = [{"correlation_type": "api_exposure", "confidence": "high",
                "severity": "info", "title": "API Surface",
                "is_inventory": True}]
    assert build_alerts([], security_stories=stories) == []


# ---------------------------------------------------------------------------
# Notification policy (Task 8/9)
# ---------------------------------------------------------------------------


def test_monitoring_mode_intervals() -> None:
    assert MonitoringMode.DAILY.interval_days == 1
    assert MonitoringMode.EVERY_3_DAYS.interval_days == 3
    assert MonitoringMode.WEEKLY.interval_days == 7
    assert MonitoringMode.MONTHLY.interval_days == 30
    assert MonitoringMode.MANUAL.interval_days is None


def test_critical_only_policy() -> None:
    pol = NotificationPolicy(frequency=NotificationFrequency.CRITICAL_ONLY)
    assert pol.should_deliver(AlertTier.CRITICAL)
    assert not pol.should_deliver(AlertTier.WARNING)
    assert pol.is_immediate(AlertTier.CRITICAL)


def test_critical_always_immediate_even_on_weekly_digest() -> None:
    pol = NotificationPolicy(frequency=NotificationFrequency.WEEKLY_DIGEST)
    assert pol.is_immediate(AlertTier.CRITICAL) is True
    assert pol.is_immediate(AlertTier.WARNING) is False  # deferred to digest


def test_plan_delivery_splits_alerts() -> None:
    pol = NotificationPolicy(frequency=NotificationFrequency.DAILY_DIGEST)
    alerts = [
        Alert(tier=AlertTier.CRITICAL, category="security_change",
              title="c", story="", recommended_action=""),
        Alert(tier=AlertTier.WARNING, category="security_change",
              title="w", story="", recommended_action=""),
        Alert(tier=AlertTier.INFORMATIONAL, category="content_change",
              title="i", story="", recommended_action=""),
        Alert(tier=AlertTier.REVIEW, category="vendor_change", title="s",
              story="", recommended_action="", suppressed=True),
    ]
    plan = plan_delivery(alerts, pol)
    assert len(plan.immediate) == 1          # critical
    assert len(plan.digest) == 1             # warning batched
    assert len(plan.suppressed) == 1         # informational below floor
    # The already-suppressed alert never reaches delivery.
    titles = [a.title for a in plan.immediate + plan.digest + plan.suppressed]
    assert "s" not in titles


def test_custom_policy_honours_min_tier() -> None:
    pol = NotificationPolicy(frequency=NotificationFrequency.CUSTOM,
                             min_tier=AlertTier.NOTICE)
    assert pol.should_deliver(AlertTier.NOTICE)
    assert pol.is_immediate(AlertTier.NOTICE)
    assert not pol.should_deliver(AlertTier.INFORMATIONAL)
