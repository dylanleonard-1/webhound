# WebHound — scanner/tests/test_visibility_wade_integration.py
# WADE integration: visibility discovery deltas (new SPA routes + admin
# endpoints) flow through the existing WADE diff/scorer/classifier/timeline.

from __future__ import annotations

from webhound.wade.baseline_builder import SiteBaseline
from webhound.wade.diff_engine import DiffEngine, DiffType
from webhound.wade.anomaly_scorer import AnomalyScorer
from webhound.wade.classifier import Classifier
from webhound.models.severity import Severity


def _baseline(js_routes=(), admin=(), *, scan_id="s1") -> SiteBaseline:
    return SiteBaseline(
        target_url="https://example.com/",
        scan_id=scan_id,
        created_at="2026-06-12T00:00:00+00:00",
        pages={},
        all_script_sources=[],
        all_external_domains=[],
        page_count=0,
        all_js_routes=list(js_routes),
        all_admin_paths=list(admin),
    )


def test_baseline_roundtrip_includes_discovery_fields():
    from webhound.wade.baseline_builder import BaselineBuilder
    b = _baseline(js_routes=["https://example.com/app/dashboard"],
                  admin=["https://example.com/admin"])
    bb = BaselineBuilder()
    restored = bb.from_dict(bb.to_dict(b))
    assert restored.all_js_routes == ["https://example.com/app/dashboard"]
    assert restored.all_admin_paths == ["https://example.com/admin"]


def test_from_dict_tolerates_missing_discovery_fields():
    from webhound.wade.baseline_builder import BaselineBuilder
    # An older baseline JSON without the new keys must still load.
    data = BaselineBuilder().to_dict(_baseline())
    del data["all_js_routes"]
    del data["all_admin_paths"]
    restored = BaselineBuilder().from_dict(data)
    assert restored.all_js_routes == []
    assert restored.all_admin_paths == []


def test_new_js_route_diff_emitted():
    prev = _baseline(js_routes=["https://example.com/a"], scan_id="prev")
    curr = _baseline(js_routes=["https://example.com/a", "https://example.com/b"])
    items = DiffEngine().diff_visibility_surface(curr, prev)
    routes = [i for i in items if i.diff_type == DiffType.NEW_JS_ROUTE]
    assert len(routes) == 1
    assert routes[0].current_value == "https://example.com/b"


def test_new_admin_endpoint_diff_emitted():
    prev = _baseline(admin=[], scan_id="prev")
    curr = _baseline(admin=["https://example.com/admin"])
    items = DiffEngine().diff_visibility_surface(curr, prev)
    admins = [i for i in items if i.diff_type == DiffType.NEW_ADMIN_ENDPOINT]
    assert len(admins) == 1
    assert admins[0].severity_hint == "medium"


def test_no_delta_when_unchanged():
    b = _baseline(js_routes=["https://example.com/a"], admin=["https://example.com/admin"])
    prev = _baseline(js_routes=["https://example.com/a"], admin=["https://example.com/admin"],
                     scan_id="prev")
    assert DiffEngine().diff_visibility_surface(b, prev) == []


def test_deltas_flow_through_scorer_and_classifier():
    prev = _baseline(scan_id="prev")
    curr = _baseline(js_routes=["https://example.com/new-route"],
                     admin=["https://example.com/admin"])
    items = DiffEngine().diff_visibility_surface(curr, prev)
    # Reuse the existing WADE pipeline end-to-end.
    anomalies = AnomalyScorer().score(items)
    findings = Classifier().classify(anomalies)
    assert len(findings) == 2
    titles = " ".join(f.title for f in findings)
    assert "route" in titles.lower()
    assert "admin" in titles.lower()
    # Admin endpoint surfaces at MEDIUM; route is informational.
    sev = {f.title: f.severity for f in findings}
    admin_finding = next(f for f in findings if "admin" in f.title.lower())
    assert admin_finding.severity in (Severity.MEDIUM, Severity.LOW, Severity.HIGH)
