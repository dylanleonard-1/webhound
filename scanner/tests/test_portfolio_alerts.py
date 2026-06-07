# WebHound — tests/test_portfolio_alerts.py
# Phase-17 Task 3/4/5: client groups, cross-site alerts, portfolio WADE.

from __future__ import annotations

from webhound.portfolio.client_groups import (
    ClientGroup,
    ClientGroupManager,
    GroupType,
)
from webhound.portfolio.portfolio_alerts import (
    CrossSiteAlertType,
    CrossSiteSeverity,
    compare_sites,
    detect_cross_site_alerts,
    summarize_portfolio_wade,
)
from webhound.portfolio.site_registry import (
    SiteRecord,
    SiteRegistry,
    SiteScanSummary,
)


def _site(sid, *, vendors=(), corr=(), compromise=False, level="low",
          groups=(), tls=False, admin=False, failed=False, wade=False,
          new_scripts=(), failing_engines=(), direction=None) -> SiteRecord:
    return SiteRecord(
        site_id=sid, url=f"https://{sid}.test", groups=list(groups),
        summary=SiteScanSummary(
            risk_level=level, third_party_domains=list(vendors),
            threat_correlation_types=list(corr),
            has_compromise_story=compromise, scan_count=1,
            last_scan_at="2026-06-07T00:00:00Z",
            has_tls_issue=tls, has_admin_exposure=admin, scan_failed=failed,
            wade_changed=wade, new_script_hosts=list(new_scripts),
            failing_engines=list(failing_engines), risk_direction=direction))


def _types(alerts):
    return {a.alert_type for a in alerts}


# ---------------------------------------------------------------------------
# Client groups (Task 4)
# ---------------------------------------------------------------------------


def test_client_group_rollup() -> None:
    reg = SiteRegistry()
    reg.add(_site("a", level="high", groups=["client1"]))
    reg.add(_site("b", level="safe", groups=["client1"]))
    reg.add(_site("c", level="medium", groups=["client2"]))
    mgr = ClientGroupManager(reg)
    mgr.add_group(ClientGroup("client1", "Acme Corp",
                              GroupType.AGENCY_CLIENT.value))
    mgr.add_group(ClientGroup("client2", "Beta LLC",
                              GroupType.FRANCHISE_LOCATION.value))
    r1 = mgr.rollup_group("client1")
    assert r1.site_count == 2
    assert "portfolio_risk_score" in r1.scores
    # rollup_all orders highest-risk group first.
    allr = mgr.rollup_all()
    assert allr[0].site_count >= 1


def test_groups_of_type() -> None:
    reg = SiteRegistry()
    mgr = ClientGroupManager(reg)
    mgr.add_group(ClientGroup("g1", "Store 1",
                              GroupType.STORE_LOCATION.value))
    mgr.add_group(ClientGroup("g2", "Store 2",
                              GroupType.STORE_LOCATION.value))
    mgr.add_group(ClientGroup("g3", "HQ", GroupType.BUSINESS_UNIT.value))
    assert len(mgr.groups_of_type(GroupType.STORE_LOCATION.value)) == 2


# ---------------------------------------------------------------------------
# Cross-site alerts (Task 3)
# ---------------------------------------------------------------------------


def test_shared_unknown_vendor_alerts() -> None:
    sites = [
        _site("a", vendors=["weird-vendor-xyz.com"]),
        _site("b", vendors=["weird-vendor-xyz.com"]),
        _site("c", vendors=["other.com"]),
    ]
    alerts = detect_cross_site_alerts(sites)
    vendor_alerts = [a for a in alerts
                     if a.alert_type == CrossSiteAlertType.SHARED_VENDOR_RISK]
    assert vendor_alerts
    assert vendor_alerts[0].affected_count == 2
    assert "weird-vendor-xyz.com" in vendor_alerts[0].shared_indicator


def test_shared_trusted_vendor_not_alerted() -> None:
    """An agency using Google Analytics on every site is normal."""
    sites = [_site(f"s{i}", vendors=["www.google-analytics.com"])
             for i in range(5)]
    alerts = detect_cross_site_alerts(sites)
    assert CrossSiteAlertType.SHARED_VENDOR_RISK not in _types(alerts)


def test_shared_threat_indicator_alerts() -> None:
    sites = [
        _site("a", corr=["supply_chain_risk"]),
        _site("b", corr=["supply_chain_risk"]),
    ]
    alerts = detect_cross_site_alerts(sites)
    assert CrossSiteAlertType.SHARED_THREAT_INDICATOR in _types(alerts)


def test_shared_compromise_is_critical() -> None:
    sites = [_site("a", compromise=True), _site("b", compromise=True)]
    alerts = detect_cross_site_alerts(sites)
    comp = [a for a in alerts
            if a.alert_type == CrossSiteAlertType.SHARED_COMPROMISE]
    assert comp
    assert comp[0].severity == CrossSiteSeverity.CRITICAL


def test_widespread_high_risk_alert() -> None:
    sites = [_site(f"s{i}", level="high") for i in range(4)]
    alerts = detect_cross_site_alerts(sites)
    assert CrossSiteAlertType.WIDESPREAD_ISSUE in _types(alerts)


def test_single_site_no_cross_alerts() -> None:
    assert detect_cross_site_alerts([_site("a", vendors=["x.com"])]) == []


# ---------------------------------------------------------------------------
# Phase-16 portfolio alert types
# ---------------------------------------------------------------------------


def test_multi_site_tls_issue() -> None:
    alerts = detect_cross_site_alerts(
        [_site("a", tls=True), _site("b", tls=True), _site("c")])
    a = next(x for x in alerts
             if x.alert_type == CrossSiteAlertType.MULTI_SITE_TLS_ISSUE)
    assert a.affected_count == 2


def test_multi_site_admin_exposure() -> None:
    alerts = detect_cross_site_alerts(
        [_site("a", admin=True), _site("b", admin=True)])
    assert CrossSiteAlertType.MULTI_SITE_ADMIN_EXPOSURE in _types(alerts)


def test_multi_site_scan_failure() -> None:
    alerts = detect_cross_site_alerts(
        [_site("a", failed=True), _site("b", failed=True)])
    assert CrossSiteAlertType.MULTI_SITE_SCAN_FAILURE in _types(alerts)


def test_multi_site_wade_change() -> None:
    alerts = detect_cross_site_alerts(
        [_site("a", wade=True), _site("b", wade=True), _site("c", wade=True)])
    a = next(x for x in alerts
             if x.alert_type == CrossSiteAlertType.MULTI_SITE_WADE_CHANGE)
    assert a.affected_count == 3


def test_shared_new_script_change() -> None:
    alerts = detect_cross_site_alerts([
        _site("a", new_scripts=["new-tracker-xyz.com"]),
        _site("b", new_scripts=["new-tracker-xyz.com"]),
    ])
    a = next(x for x in alerts
             if x.alert_type == CrossSiteAlertType.SHARED_SCRIPT_CHANGE)
    assert "new-tracker-xyz.com" in a.shared_indicator


def test_shared_new_trusted_script_not_alerted() -> None:
    alerts = detect_cross_site_alerts([
        _site("a", new_scripts=["www.google-analytics.com"]),
        _site("b", new_scripts=["www.google-analytics.com"]),
    ])
    assert CrossSiteAlertType.SHARED_SCRIPT_CHANGE not in _types(alerts)


def test_shared_engine_failure() -> None:
    alerts = detect_cross_site_alerts([
        _site(f"s{i}", failing_engines=["tls_checker"]) for i in range(3)])
    eng_alerts = [x for x in alerts
                  if x.shared_indicator == "tls_checker"]
    assert eng_alerts


def test_no_duplicate_alerts() -> None:
    """Task 5/10: the same (type, indicator, affected set) never appears
    twice. Build a portfolio that would otherwise emit overlapping
    alerts and assert each is unique."""
    sites = [
        _site("a", vendors=["weird-x.com"], new_scripts=["weird-x.com"],
              tls=True, admin=True, wade=True, corr=["supply_chain_risk"],
              compromise=True),
        _site("b", vendors=["weird-x.com"], new_scripts=["weird-x.com"],
              tls=True, admin=True, wade=True, corr=["supply_chain_risk"],
              compromise=True),
    ]
    alerts = detect_cross_site_alerts(sites)
    keys = [(a.alert_type.value, a.shared_indicator or "",
             tuple(sorted(a.affected_site_ids))) for a in alerts]
    assert len(keys) == len(set(keys)), "duplicate cross-site alerts emitted"


# ---------------------------------------------------------------------------
# Portfolio WADE summary (Task 5) — grouped, not duplicated
# ---------------------------------------------------------------------------


def test_portfolio_wade_summary_answers_questions() -> None:
    sites = [
        _site("a", wade=True, corr=["possible_compromise"],
              new_scripts=["new-vendor.com"], direction="increased"),
        _site("b", wade=True, new_scripts=["new-vendor.com"],
              direction="decreased"),
        _site("c"),  # unchanged
    ]
    w = summarize_portfolio_wade(sites).to_dict()
    assert set(w["sites_changed"]) == {"a", "b"}
    assert w["sites_with_suspicious_changes"] == ["a"]
    assert set(w["sites_with_new_third_parties"]) == {"a", "b"}
    assert w["sites_riskier"] == ["a"]
    assert w["sites_improved"] == ["b"]
    # The shared new script is grouped into ONE entry, not per-site.
    assert len(w["shared_changes"]) == 1
    assert w["shared_changes"][0]["site_count"] == 2


def test_portfolio_wade_empty() -> None:
    w = summarize_portfolio_wade([_site("a"), _site("b")]).to_dict()
    assert w["sites_changed"] == []
    assert w["shared_changes"] == []


# ---------------------------------------------------------------------------
# Portfolio WADE (Task 5)
# ---------------------------------------------------------------------------


def test_portfolio_diff_finds_shared_and_outliers() -> None:
    sites = [
        _site("loc1", vendors=["shared-cms.com", "common-cdn.com"]),
        _site("loc2", vendors=["shared-cms.com", "common-cdn.com"]),
        _site("loc3", vendors=["shared-cms.com", "common-cdn.com",
                               "rogue-unique-host.com"]),
    ]
    diff = compare_sites(sites)
    assert "shared-cms.com" in diff.shared_vendors
    # loc3 carries a vendor none of its peers have.
    outliers = {o["site_id"] for o in diff.outlier_sites}
    assert "loc3" in outliers


def test_portfolio_diff_single_site() -> None:
    diff = compare_sites([_site("a", vendors=["x.com"])])
    assert diff.shared_vendors == []
    assert diff.outlier_sites == []
