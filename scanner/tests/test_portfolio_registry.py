# WebHound — tests/test_portfolio_registry.py
# Phase-17 Task 1: site registry + scan summary + site health.

from __future__ import annotations

from webhound.portfolio.site_health import (
    HealthStatus,
    assess_site_health,
)
from webhound.portfolio.site_registry import (
    SiteRecord,
    SiteRegistry,
    SiteScanSummary,
)


def _summary(**kw) -> SiteScanSummary:
    base = dict(risk_score=10, risk_level="low", scan_count=1,
                last_scan_at="2026-06-07T00:00:00Z")
    base.update(kw)
    return SiteScanSummary(**base)


def _site(sid, **kw) -> SiteRecord:
    summary = kw.pop("summary", _summary())
    return SiteRecord(site_id=sid, url=f"https://{sid}.test",
                      summary=summary, **kw)


# ---------------------------------------------------------------------------
# Scan summary extraction
# ---------------------------------------------------------------------------


def test_summary_from_scan_metadata() -> None:
    meta = {
        "risk_score": 55, "risk_level": "medium",
        "risk_breakdown": {"type_counts": {"confirmed_risk": 2,
                                           "hardening": 3}},
        "external_script_domains": ["cdn.vendor.com"],
        "security_stories": [{"correlation_type": "possible_compromise"}],
        "threat_correlations": [{"correlation_type": "supply_chain_risk"}],
        "frameworks": {"primary_framework": "WordPress"},
        "wade_timeline": {"recurring_count": 2},
    }
    s = SiteScanSummary.from_scan_metadata(meta)
    assert s.risk_score == 55
    assert s.confirmed_risk_count == 2
    assert s.has_compromise_story is True
    assert "supply_chain_risk" in s.threat_correlation_types
    assert s.framework == "WordPress"
    assert s.change_frequency == 2
    assert "cdn.vendor.com" in s.third_party_domains


def test_summary_from_empty_metadata_safe() -> None:
    s = SiteScanSummary.from_scan_metadata(None)
    assert s.risk_score == 0
    assert s.risk_level == "safe"
    assert s.has_compromise_story is False


# ---------------------------------------------------------------------------
# Registry (1 → 100+ sites)
# ---------------------------------------------------------------------------


def test_registry_add_query_filter() -> None:
    reg = SiteRegistry()
    reg.add(_site("a", organization="acme", tags=["prod"],
                  groups=["client1"], industry="retail"))
    reg.add(_site("b", organization="acme", tags=["staging"],
                  groups=["client1"]))
    reg.add(_site("c", organization="other", groups=["client2"]))
    assert reg.count == 3
    assert {s.site_id for s in reg.by_organization("acme")} == {"a", "b"}
    assert [s.site_id for s in reg.by_tag("prod")] == ["a"]
    assert {s.site_id for s in reg.by_group("client1")} == {"a", "b"}
    assert [s.site_id for s in reg.by_industry("retail")] == ["a"]


def test_registry_scales_to_100_sites() -> None:
    reg = SiteRegistry.from_records(
        _site(f"s{i}", groups=[f"g{i % 5}"]) for i in range(120))
    assert reg.count == 120
    assert len(reg.by_group("g0")) == 24


def test_registry_update_summary() -> None:
    reg = SiteRegistry()
    reg.add(_site("a"))
    assert reg.update_summary("a", _summary(risk_score=80, risk_level="high"))
    assert reg.get("a").summary.risk_score == 80
    assert reg.update_summary("missing", _summary()) is False


# ---------------------------------------------------------------------------
# Site health
# ---------------------------------------------------------------------------


def test_healthy_site() -> None:
    h = assess_site_health(_site("a", summary=_summary(
        risk_score=5, risk_level="safe")))
    assert h.status == HealthStatus.HEALTHY


def test_compromise_is_critical_health() -> None:
    h = assess_site_health(_site("a", summary=_summary(
        risk_level="high", has_compromise_story=True)))
    assert h.status == HealthStatus.CRITICAL
    assert any("compromise" in r for r in h.reasons)


def test_unmonitored_site() -> None:
    h = assess_site_health(_site("a", summary=SiteScanSummary(
        scan_count=0, last_scan_at=None)))
    assert h.status == HealthStatus.UNMONITORED
    assert h.health_score == 100


def test_confirmed_risks_raise_health_score() -> None:
    low = assess_site_health(_site("a", summary=_summary(risk_level="medium")))
    high = assess_site_health(_site("b", summary=_summary(
        risk_level="medium",
        finding_type_counts={"confirmed_risk": 3})))
    assert high.health_score > low.health_score
