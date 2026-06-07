# WebHound — tests/test_change_tracker.py
# Phase-11 Task 1/2: cross-scan change accumulation.

from __future__ import annotations

from webhound.monitoring.change_history import ChangeHistory
from webhound.monitoring.change_tracker import track_scan


def _timeline(records):
    return {"records": records}


def _rec(key, diff_type, *, change_type="normal_content_update",
         band="low", url="https://t.test/", value=None):
    return {"change_key": key, "diff_type": diff_type,
            "change_type": change_type, "band": band, "url": url,
            "value": value}


def test_new_script_tracked_as_security() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "new_script_source", band="medium",
             value="https://cdn.x/a.js")]),
        scan_timestamp="2026-05-01T00:00:00Z", target="https://t.test")
    e = h.records["k1"]
    assert e.asset == "script"
    assert e.category == "security_change"
    assert e.direction == "increased"
    assert e.tier == "review"          # band=medium
    assert e.occurrences == 1
    assert h.scan_count == 1
    assert h.target == "https://t.test"


def test_recurring_change_accumulates() -> None:
    h = ChangeHistory()
    tl = _timeline([_rec("k1", "new_external_domain", value="x.test")])
    track_scan(h, wade_timeline=tl, scan_timestamp="2026-05-01T00:00:00Z")
    track_scan(h, wade_timeline=tl, scan_timestamp="2026-05-08T00:00:00Z")
    e = h.records["k1"]
    assert e.occurrences == 2
    assert e.first_seen == "2026-05-01T00:00:00Z"
    assert e.last_seen == "2026-05-08T00:00:00Z"
    assert e.is_recurring
    assert h.scan_count == 2


def test_header_added_decreases_risk() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "header_added", value="content-security-policy")]),
        scan_timestamp="t")
    assert h.records["k1"].direction == "decreased"
    assert h.records["k1"].category == "security_change"


def test_header_regression_increases_risk() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "header_regression", value="x-frame-options")]),
        scan_timestamp="t")
    assert h.records["k1"].direction == "increased"


def test_payment_provider_categorised() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "new_external_domain", change_type="new_payment_provider",
             value="js.stripe.com")]), scan_timestamp="t")
    assert h.records["k1"].category == "payment_change"


def test_suspicious_change_is_possible_compromise() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "new_iframe", change_type="suspicious_iframe",
             band="high", value="evil.test")]), scan_timestamp="t")
    e = h.records["k1"]
    assert e.category == "possible_compromise"
    assert e.direction == "increased"
    assert e.tier == "warning"


def test_removed_script_decreases() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=_timeline([
        _rec("k1", "removed_script_source", value="old.js")]),
        scan_timestamp="t")
    assert h.records["k1"].direction == "decreased"


def test_empty_timeline_safe() -> None:
    h = ChangeHistory()
    track_scan(h, wade_timeline=None, scan_timestamp="t")
    track_scan(h, wade_timeline={"records": []}, scan_timestamp="t")
    assert h.total_changes == 0
    assert h.scan_count == 2
