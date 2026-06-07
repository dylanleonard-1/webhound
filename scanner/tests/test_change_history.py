# WebHound — tests/test_change_history.py
# Phase-11 monitoring: ChangeEvent / ChangeHistory model — the persistent
# structure the rest of the layer accumulates and the dashboard renders.

from __future__ import annotations

from webhound.monitoring.change_history import (
    AlertTier,
    ChangeCategory,
    ChangeEvent,
    ChangeHistory,
    RiskDirection,
    TrackedAsset,
)


def _ev(key="k1", tier=AlertTier.NOTICE, occurrences=1,
        last_seen="2026-05-08T00:00:00Z") -> ChangeEvent:
    return ChangeEvent(
        change_key=key, asset=TrackedAsset.SCRIPT.value,
        category=ChangeCategory.VENDOR.value, tier=tier.value,
        direction=RiskDirection.UNCHANGED.value,
        title="Google Analytics added", first_seen="2026-05-01T00:00:00Z",
        last_seen=last_seen, occurrences=occurrences)


def test_alert_tier_ordering() -> None:
    assert AlertTier.CRITICAL.rank > AlertTier.WARNING.rank
    assert AlertTier.WARNING.rank > AlertTier.REVIEW.rank
    assert AlertTier.REVIEW.rank > AlertTier.NOTICE.rank
    assert AlertTier.NOTICE.rank > AlertTier.INFORMATIONAL.rank


def test_change_event_roundtrip() -> None:
    e = _ev(occurrences=3)
    d = e.to_dict()
    assert d["recurring"] is True
    back = ChangeEvent.from_dict(d)
    assert back.change_key == "k1"
    assert back.occurrences == 3
    assert back.title == "Google Analytics added"


def test_history_histograms_and_open_events() -> None:
    h = ChangeHistory(target="https://t.test")
    h.records["k1"] = _ev("k1", AlertTier.NOTICE)
    h.records["k2"] = _ev("k2", AlertTier.WARNING)
    h.records["k3"] = _ev("k3", AlertTier.WARNING)
    h.records["k3"].suppressed = True

    assert h.total_changes == 3
    assert h.tier_histogram() == {"notice": 1, "warning": 2}
    # Suppressed events are excluded from the open set.
    assert {e.change_key for e in h.open_events()} == {"k1", "k2"}


def test_timeline_newest_first() -> None:
    h = ChangeHistory()
    h.records["a"] = _ev("a", last_seen="2026-05-01T00:00:00Z")
    h.records["b"] = _ev("b", last_seen="2026-05-24T00:00:00Z")
    h.records["c"] = _ev("c", last_seen="2026-05-08T00:00:00Z")
    dates = [t["date"] for t in h.timeline()]
    assert dates == ["2026-05-24T00:00:00Z", "2026-05-08T00:00:00Z",
                     "2026-05-01T00:00:00Z"]
    entry = h.timeline()[0]
    assert {"date", "change", "category", "risk_impact", "confidence",
            "tier", "status"} <= set(entry)


def test_history_roundtrip() -> None:
    h = ChangeHistory(target="https://t.test", scan_count=4,
                      last_scan_at="2026-05-24T00:00:00Z")
    h.records["k1"] = _ev("k1")
    d = h.to_dict()
    back = ChangeHistory.from_dict(d)
    assert back.target == "https://t.test"
    assert back.scan_count == 4
    assert "k1" in back.records


def test_history_from_none_is_empty() -> None:
    h = ChangeHistory.from_dict(None)
    assert h.total_changes == 0
    assert h.scan_count == 0
