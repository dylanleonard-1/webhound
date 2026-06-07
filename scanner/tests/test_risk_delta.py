# WebHound — tests/test_risk_delta.py
# Phase-11 Task 5: risk delta engine.

from __future__ import annotations

from webhound.monitoring.change_history import RiskDirection
from webhound.monitoring.risk_delta import compute_risk_delta


def _meta(score, level, counts=None):
    return {
        "risk_score": score, "risk_level": level,
        "risk_breakdown": {"type_counts": counts or {}},
    }


def test_first_scan_is_unchanged_baseline() -> None:
    d = compute_risk_delta(None, _meta(20, "low"))
    assert d.direction == RiskDirection.UNCHANGED
    assert "first scan" in d.reasons[0]
    assert d.score_change == 0


def test_risk_increase_explained() -> None:
    prev = _meta(10, "safe", {"confirmed_risk": 0, "hardening": 2})
    cur = _meta(45, "medium", {"confirmed_risk": 2, "hardening": 1})
    d = compute_risk_delta(prev, cur)
    assert d.direction == RiskDirection.INCREASED
    assert d.score_change == 35
    assert d.level_changed is True
    assert any("rose from safe to medium" in r for r in d.reasons)
    assert any("+2 confirmed risks" in r for r in d.reasons)
    assert any("-1 hardening gaps" in r for r in d.reasons)


def test_risk_decrease_explained() -> None:
    prev = _meta(50, "medium", {"confirmed_risk": 2})
    cur = _meta(8, "safe", {"confirmed_risk": 0})
    d = compute_risk_delta(prev, cur)
    assert d.direction == RiskDirection.DECREASED
    assert d.score_change == -42
    assert any("fell from medium to safe" in r for r in d.reasons)
    assert any("-2 confirmed risks" in r for r in d.reasons)


def test_small_move_is_unchanged() -> None:
    d = compute_risk_delta(_meta(20, "low"), _meta(21, "low"))
    assert d.direction == RiskDirection.UNCHANGED
    assert d.reasons


def test_recalibration_without_type_shift() -> None:
    prev = _meta(20, "low", {"confirmed_risk": 1})
    cur = _meta(30, "low", {"confirmed_risk": 1})
    d = compute_risk_delta(prev, cur)
    assert d.direction == RiskDirection.INCREASED
    assert any("recalibration" in r for r in d.reasons)


def test_to_dict_shape() -> None:
    d = compute_risk_delta(_meta(10, "safe"), _meta(40, "medium"))
    out = d.to_dict()
    assert out["direction"] == "increased"
    assert out["score_change"] == 30
    assert out["level_changed"] is True
