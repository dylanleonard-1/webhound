# WebHound API — apps/api/tests/test_portfolio_service.py
# Phase-16: the portfolio aggregation core. The pure build_portfolio_view
# is tested with synthetic SiteRows — no DB, no Redis — so the agency/MSP
# rollup logic is verifiable anywhere.

from __future__ import annotations

from apps.api.services.portfolio import SiteRow, build_portfolio_view


def _row(sid, *, domain=None, score=10, level="low", group=None,
         meta=None, scanned=True, failed=False, tls=False) -> SiteRow:
    return SiteRow(
        site_id=sid, domain=domain or f"{sid}.test",
        url=f"https://{domain or sid + '.test'}",
        risk_score=score, risk_level=level, group_id=group,
        scanner_metadata=meta, scan_failed=failed, has_tls_issue=tls,
        last_scan_at="2026-06-07T00:00:00Z" if scanned else None,
        monitoring=scanned)


# ---------------------------------------------------------------------------
# Backward compatibility (Task 9): single-site works exactly as a 1-site
# portfolio.
# ---------------------------------------------------------------------------


def test_single_site_portfolio() -> None:
    v = build_portfolio_view([_row("only", score=45, level="medium")])
    assert v["summary"]["sites_monitored"] == 1
    assert "portfolio_risk_score" in v["summary"]
    assert v["report"]["summary"]["sites_monitored"] == 1


def test_empty_portfolio() -> None:
    v = build_portfolio_view([])
    assert v["summary"]["sites_monitored"] == 0
    assert "No sites" in v["report"]["narrative"]


# ---------------------------------------------------------------------------
# Rollup + scores (Task 3)
# ---------------------------------------------------------------------------


def test_ten_site_agency_rollup() -> None:
    rows = [_row(f"s{i}", level="low", score=15) for i in range(8)]
    rows += [_row("bad1", level="high", score=70),
             _row("bad2", level="critical", score=95,
                  meta={"security_stories":
                        [{"correlation_type": "possible_compromise"}]})]
    v = build_portfolio_view(rows)
    assert v["summary"]["sites_monitored"] == 10
    assert v["summary"]["sites_with_compromise"] == 1
    assert v["dashboard"]["most_vulnerable_sites"]
    assert "portfolio_health_score" in v["summary"]


def test_fifty_site_msp() -> None:
    rows = [_row(f"store{i}", level="low",
                 meta={"external_script_domains": ["shared-pos-xyz.com"]})
            for i in range(50)]
    v = build_portfolio_view(rows)
    assert v["summary"]["sites_monitored"] == 50
    # Shared unrecognised vendor across 50 stores → a cross-site alert.
    assert v["summary"]["cross_site_alert_count"] >= 1


def test_risk_distribution_present() -> None:
    rows = [_row("a", level="high"), _row("b", level="safe"),
            _row("c", level="medium")]
    v = build_portfolio_view(rows)
    dist = v["dashboard"]["risk_distribution"]
    assert dist.get("high") == 1
    assert dist.get("safe") == 1


# ---------------------------------------------------------------------------
# Report (Task 6) + branding (Task 7) + trend
# ---------------------------------------------------------------------------


def test_report_sections_and_branding() -> None:
    v = build_portfolio_view(
        [_row("a", level="high", score=70)],
        branding={"agency_name": "SecureAgency",
                  "hide_webhound_branding": True})
    report = v["report"]
    assert report["branding"]["agency_name"] == "SecureAgency"
    for key in ("summary", "top_risks", "portfolio_health", "narrative"):
        assert key in report


def test_report_trend_vs_previous() -> None:
    v = build_portfolio_view(
        [_row("a", level="high", score=70)],
        previous_scores={"portfolio_risk_score": 30})
    assert v["report"]["trend"]["direction"] == "increased"


# ---------------------------------------------------------------------------
# Per-site operational signals flow through (Task 4 inputs)
# ---------------------------------------------------------------------------


def test_failed_and_tls_signals_carry() -> None:
    """API-supplied scan_failed + has_tls_issue signals reach the
    cross-site detectors (MULTI_SITE_TLS_ISSUE / SCAN_FAILURE)."""
    rows = [_row("a", failed=True, tls=True),
            _row("b", failed=True, tls=True)]
    v = build_portfolio_view(rows)
    assert v["summary"]["cross_site_alert_count"] >= 1
    types = set(v["dashboard"]["alert_distribution"])  # severity keys present
    assert types
