# WebHound — scanner/webhound/portfolio/portfolio_score.py
# Phase-17 Task 2: the four portfolio-level scores a customer/agency
# tracks — Risk, Health, Monitoring, and Stability — each 0-100 with a
# plain band, built from the risk rollup + per-site health + monitoring
# freshness + change churn.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webhound.portfolio.risk_rollup import build_risk_rollup
from webhound.portfolio.site_health import HealthStatus, assess_site_health
from webhound.portfolio.site_registry import SiteRecord


def _band(score: int, *, higher_is_better: bool) -> str:
    s = score if higher_is_better else 100 - score
    if s >= 85:
        return "excellent"
    if s >= 65:
        return "good"
    if s >= 45:
        return "fair"
    if s >= 25:
        return "poor"
    return "critical"


@dataclass
class PortfolioScores:
    risk_score: int                    # 0 best (low risk) .. 100 worst
    health_score: int                  # 0-100, higher = healthier
    monitoring_score: int              # 0-100, higher = better coverage
    stability_score: int               # 0-100, higher = more stable
    risk_band: str
    health_band: str
    monitoring_band: str
    stability_band: str
    site_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "portfolio_risk_score": self.risk_score,
            "portfolio_health_score": self.health_score,
            "portfolio_monitoring_score": self.monitoring_score,
            "portfolio_stability_score": self.stability_score,
            "risk_band": self.risk_band,
            "health_band": self.health_band,
            "monitoring_band": self.monitoring_band,
            "stability_band": self.stability_band,
            "site_count": self.site_count,
        }


def compute_portfolio_scores(sites: list[SiteRecord]) -> PortfolioScores:
    """Compute the four portfolio scores."""
    n = len(sites)
    if n == 0:
        return PortfolioScores(
            risk_score=0, health_score=100, monitoring_score=0,
            stability_score=100, risk_band="excellent", health_band="excellent",
            monitoring_band="critical", stability_band="excellent",
            site_count=0)

    rollup = build_risk_rollup(sites)
    health = [assess_site_health(r) for r in sites]

    # Risk: the weighted portfolio risk (0 best, 100 worst).
    risk = rollup.weighted_portfolio_risk

    # Health: inverse of the average per-site health score (which is
    # 0 best, 100 worst) → 100 best.
    avg_health_burden = sum(h.health_score for h in health) / n
    health_score = int(round(100 - avg_health_burden))

    # Monitoring: share of sites actually scanned recently.
    monitored = sum(1 for h in health
                    if h.status != HealthStatus.UNMONITORED)
    monitoring_score = int(round(monitored / n * 100))

    # Stability: inverse of average change churn (capped) — a portfolio
    # whose sites change constantly is less stable.
    avg_churn = sum(r.summary.change_frequency for r in sites) / n
    stability_burden = min(100, avg_churn * 20)
    stability_score = int(round(100 - stability_burden))

    return PortfolioScores(
        risk_score=risk,
        health_score=max(0, min(100, health_score)),
        monitoring_score=max(0, min(100, monitoring_score)),
        stability_score=max(0, min(100, stability_score)),
        risk_band=_band(risk, higher_is_better=False),
        health_band=_band(health_score, higher_is_better=True),
        monitoring_band=_band(monitoring_score, higher_is_better=True),
        stability_band=_band(stability_score, higher_is_better=True),
        site_count=n)
