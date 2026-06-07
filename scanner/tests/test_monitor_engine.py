# WebHound — tests/test_monitor_engine.py
# Phase-11 orchestration: run_monitoring ties tracking + risk delta +
# alerts + delivery + timeline together across scans (Task 11 e2e).

from __future__ import annotations

from webhound.monitoring import (
    AlertTier,
    ChangeHistory,
    NotificationFrequency,
    NotificationPolicy,
    run_monitoring,
)


def _meta(score=10, level="safe", records=None, stories=None, counts=None):
    return {
        "risk_score": score, "risk_level": level,
        "risk_breakdown": {"type_counts": counts or {}},
        "wade_timeline": {"records": records or []},
        "security_stories": stories or [],
    }


def _rec(key, diff_type, *, change_type="normal_content_update",
         band="low", url="https://t.test/login", value=None):
    return {"change_key": key, "diff_type": diff_type,
            "change_type": change_type, "band": band, "url": url,
            "value": value}


def test_first_scan_establishes_history() -> None:
    res = run_monitoring(
        current_meta=_meta(records=[
            _rec("k1", "new_script_source", band="medium",
                 value="https://cdn.x/a.js")]),
        previous_meta=None, prior_history=None,
        scan_timestamp="2026-05-01T00:00:00Z", target="https://t.test")
    assert res.history.scan_count == 1
    assert res.history.total_changes == 1
    assert res.risk_delta.direction.value == "unchanged"  # first scan
    assert res.to_dict()["timeline"]


def test_second_scan_accumulates_and_alerts() -> None:
    # Scan 1: a new unknown script on the login page.
    r1 = run_monitoring(
        current_meta=_meta(records=[
            _rec("k1", "new_script_source", change_type="suspicious_script_change",
                 band="high", value="https://evil.x/a.js")]),
        scan_timestamp="2026-05-01T00:00:00Z", target="https://t.test")
    # Scan 2: a NEW iframe appears + risk rises.
    r2 = run_monitoring(
        current_meta=_meta(score=55, level="medium", counts={"confirmed_risk": 1},
                           records=[
            _rec("k2", "new_iframe", change_type="suspicious_iframe",
                 band="high", value="evil.x")]),
        previous_meta=_meta(score=10, level="safe"),
        prior_history=r1.history,
        scan_timestamp="2026-05-08T00:00:00Z", target="https://t.test")

    assert r2.history.scan_count == 2
    assert r2.history.total_changes == 2          # k1 + k2 accumulated
    # The new iframe (possible compromise) is a warning+ active alert.
    assert any(a.category == "possible_compromise" for a in r2.active_alerts)
    # Risk increased and produced its own alert.
    assert r2.risk_delta.direction.value == "increased"
    assert any("Risk score increased" in a.title for a in r2.alerts)


def test_expected_deployment_suppressed_end_to_end() -> None:
    res = run_monitoring(
        current_meta=_meta(records=[
            _rec("k1", "new_external_domain", change_type="new_analytics_tool",
                 band="very_low", value="expected_deployment ga.test")]),
        scan_timestamp="t", target="https://t.test")
    # Analytics + expected marker → suppressed, no active alert.
    assert res.active_alerts == [] or all(
        a.suppressed for a in res.alerts if a.title != "")


def test_delivery_plan_respects_policy() -> None:
    res = run_monitoring(
        current_meta=_meta(records=[
            _rec("k1", "new_iframe", change_type="confirmed_malicious_indicator",
                 band="critical", value="evil.x")]),
        scan_timestamp="t", target="https://t.test",
        policy=NotificationPolicy(
            frequency=NotificationFrequency.CRITICAL_ONLY))
    # A confirmed malicious indicator → critical → delivered immediately.
    assert res.delivery is not None
    assert len(res.delivery.immediate) >= 1
    assert all(a.tier == AlertTier.CRITICAL for a in res.delivery.immediate)


def test_monitor_result_serializable() -> None:
    res = run_monitoring(
        current_meta=_meta(records=[_rec("k1", "new_form", band="low")]),
        scan_timestamp="t", target="https://t.test")
    d = res.to_dict()
    assert "risk_delta" in d
    assert "alerts" in d
    assert "timeline" in d
    assert "history_summary" in d


def test_recurring_change_not_respammed() -> None:
    tl = [_rec("k1", "new_external_domain", change_type="new_marketing_tool",
               band="low", value="vendor.test")]
    r1 = run_monitoring(current_meta=_meta(records=tl),
                        scan_timestamp="d1", target="https://t.test")
    r2 = run_monitoring(current_meta=_meta(records=tl),
                        previous_meta=_meta(), prior_history=r1.history,
                        scan_timestamp="d2", target="https://t.test")
    # The same low-tier vendor change, seen again, is suppressed in scan 2.
    k1_alerts = [a for a in r2.alerts if "k1" in a.change_keys]
    assert k1_alerts and k1_alerts[0].suppressed
