# WebHound — tests/test_portfolio_report.py
# Phase-17 Task 6/7/8: dashboard data, executive report, white-label, and
# the agency/MSP end-to-end scenarios (Task 9).

from __future__ import annotations

from webhound.portfolio import (
    BrandingConfig,
    SiteRecord,
    SiteRegistry,
    SiteScanSummary,
    build_dashboard_data,
    build_executive_report,
)


def _site(sid, *, level="low", score=10, compromise=False, churn=0,
          vendors=(), corr=(), scanned=True) -> SiteRecord:
    return SiteRecord(
        site_id=sid, url=f"https://{sid}.test",
        summary=SiteScanSummary(
            risk_score=score, risk_level=level, has_compromise_story=compromise,
            change_frequency=churn, third_party_domains=list(vendors),
            threat_correlation_types=list(corr), scan_count=1 if scanned else 0,
            last_scan_at="2026-06-07T00:00:00Z" if scanned else None))


def _registry(sites) -> SiteRegistry:
    return SiteRegistry.from_records(sites)


# ---------------------------------------------------------------------------
# Dashboard data (Task 6)
# ---------------------------------------------------------------------------


def test_dashboard_data_shape() -> None:
    reg = _registry([
        _site("a", level="high", score=70, churn=4),
        _site("b", level="safe", score=5),
        _site("c", level="critical", score=95, compromise=True),
    ])
    d = build_dashboard_data(reg)
    assert d["sites_monitored"] == 3
    assert "scores" in d and "risk_distribution" in d
    assert "health_distribution" in d
    assert d["most_vulnerable_sites"]
    assert d["most_changed_sites"][0]["site_id"] == "a"


# ---------------------------------------------------------------------------
# Agency / MSP scenarios (Task 9)
# ---------------------------------------------------------------------------


def test_single_site_customer() -> None:
    reg = _registry([_site("only", level="medium", score=45)])
    report = build_executive_report(reg).to_dict()
    assert report["summary"]["sites_monitored"] == 1
    assert "1 site" in report["narrative"]


def test_ten_site_agency() -> None:
    sites = [_site(f"s{i}", level="low", score=15) for i in range(8)]
    sites += [_site("bad1", level="high", score=70),
              _site("bad2", level="critical", score=95, compromise=True)]
    reg = _registry(sites)
    report = build_executive_report(reg).to_dict()
    assert report["summary"]["sites_monitored"] == 10
    assert report["summary"]["sites_with_compromise"] == 1
    assert report["top_risks"]


def test_fifty_site_msp_with_shared_vendor() -> None:
    # 50 stores, all loading the same unrecognised vendor → cross-site.
    sites = [_site(f"store{i}", level="low",
                   vendors=["shared-pos-vendor-xyz.com"])
             for i in range(50)]
    reg = _registry(sites)
    d = build_dashboard_data(reg)
    assert d["sites_monitored"] == 50
    assert d["cross_site_alert_count"] >= 1     # the shared vendor


def test_executive_report_branding() -> None:
    reg = _registry([_site("a")])
    branding = BrandingConfig(agency_name="SecureAgency",
                              hide_webhound_branding=True,
                              primary_color="#FF0000")
    report = build_executive_report(reg, branding=branding).to_dict()
    assert report["branding"]["agency_name"] == "SecureAgency"
    assert report["branding"]["hide_webhound_branding"] is True


def test_executive_report_trend() -> None:
    reg = _registry([_site("a", level="high", score=70)])
    report = build_executive_report(
        reg, previous_scores={"portfolio_risk_score": 30}).to_dict()
    assert report["trend"]["direction"] == "increased"
    assert "increased" in report["narrative"].lower()


def test_compromise_drives_narrative() -> None:
    reg = _registry([_site("a", level="critical", compromise=True),
                     _site("b", level="critical", compromise=True)])
    report = build_executive_report(reg).to_dict()
    assert "compromise" in report["narrative"].lower()


def test_empty_portfolio_report() -> None:
    report = build_executive_report(SiteRegistry()).to_dict()
    assert "No sites" in report["narrative"]
