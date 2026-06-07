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
)
from webhound.portfolio.site_registry import (
    SiteRecord,
    SiteRegistry,
    SiteScanSummary,
)


def _site(sid, *, vendors=(), corr=(), compromise=False, level="low",
          groups=()) -> SiteRecord:
    return SiteRecord(
        site_id=sid, url=f"https://{sid}.test", groups=list(groups),
        summary=SiteScanSummary(
            risk_level=level, third_party_domains=list(vendors),
            threat_correlation_types=list(corr),
            has_compromise_story=compromise, scan_count=1,
            last_scan_at="2026-06-07T00:00:00Z"))


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
