# WebHound — tests/test_portfolio_scoring.py
# Phase-17 Task 2/6: risk rollup + portfolio scores.

from __future__ import annotations

from webhound.portfolio.portfolio_score import compute_portfolio_scores
from webhound.portfolio.risk_rollup import build_risk_rollup
from webhound.portfolio.site_registry import (
    SiteRecord,
    SiteScanSummary,
)


def _site(sid, *, level="low", score=10, confirmed=0, compromise=False,
          churn=0, scanned=True) -> SiteRecord:
    return SiteRecord(
        site_id=sid, url=f"https://{sid}.test",
        summary=SiteScanSummary(
            risk_score=score, risk_level=level,
            finding_type_counts={"confirmed_risk": confirmed} if confirmed
            else {},
            has_compromise_story=compromise, change_frequency=churn,
            scan_count=1 if scanned else 0,
            last_scan_at="2026-06-07T00:00:00Z" if scanned else None))


# ---------------------------------------------------------------------------
# Risk rollup (Task 2/6)
# ---------------------------------------------------------------------------


def test_rollup_risk_distribution() -> None:
    sites = [_site("a", level="safe", score=5),
             _site("b", level="high", score=70),
             _site("c", level="high", score=65),
             _site("d", level="medium", score=45)]
    roll = build_risk_rollup(sites)
    assert roll.site_count == 4
    assert roll.risk_distribution == {"high": 2, "medium": 1, "safe": 1}
    assert 40 <= roll.avg_risk_score <= 50


def test_rollup_most_vulnerable_and_stable() -> None:
    sites = [
        _site("bad", level="critical", score=90, compromise=True),
        _site("ok", level="safe", score=5),
        _site("mid", level="medium", score=45, confirmed=2),
    ]
    roll = build_risk_rollup(sites)
    assert roll.most_vulnerable[0]["site_id"] == "bad"
    assert roll.sites_with_compromise == 1
    assert roll.sites_with_confirmed_risk == 1
    # The safe site is the most stable.
    assert any(s["site_id"] == "ok" for s in roll.most_stable)


def test_rollup_most_changed() -> None:
    sites = [_site("a", churn=5), _site("b", churn=1), _site("c", churn=0)]
    roll = build_risk_rollup(sites)
    assert roll.most_changed[0]["site_id"] == "a"
    assert all(s["change_frequency"] > 0 for s in roll.most_changed)


def test_rollup_empty() -> None:
    roll = build_risk_rollup([])
    assert roll.site_count == 0
    assert roll.weighted_portfolio_risk == 0


# ---------------------------------------------------------------------------
# Portfolio scores (Task 2)
# ---------------------------------------------------------------------------


def test_healthy_portfolio_scores_well() -> None:
    sites = [_site(f"s{i}", level="safe", score=5) for i in range(10)]
    sc = compute_portfolio_scores(sites)
    assert sc.risk_score <= 20
    assert sc.health_score >= 80
    assert sc.monitoring_score == 100
    assert sc.stability_score == 100
    assert sc.risk_band in ("excellent", "good")


def test_risky_portfolio_scores_poorly() -> None:
    sites = [_site(f"s{i}", level="critical", score=90, compromise=True)
             for i in range(5)]
    sc = compute_portfolio_scores(sites)
    assert sc.risk_score >= 80
    assert sc.health_score <= 25
    assert sc.health_band in ("poor", "critical")


def test_monitoring_score_reflects_coverage() -> None:
    sites = ([_site(f"m{i}", scanned=True) for i in range(7)]
             + [_site(f"u{i}", scanned=False) for i in range(3)])
    sc = compute_portfolio_scores(sites)
    assert sc.monitoring_score == 70


def test_stability_score_drops_with_churn() -> None:
    stable = compute_portfolio_scores(
        [_site(f"s{i}", churn=0) for i in range(5)])
    churny = compute_portfolio_scores(
        [_site(f"s{i}", churn=4) for i in range(5)])
    assert stable.stability_score > churny.stability_score


def test_empty_portfolio() -> None:
    sc = compute_portfolio_scores([])
    assert sc.site_count == 0
    assert sc.monitoring_band == "critical"


def test_single_site_portfolio() -> None:
    sc = compute_portfolio_scores([_site("only", level="medium", score=45)])
    assert sc.site_count == 1
    assert 0 <= sc.risk_score <= 100
