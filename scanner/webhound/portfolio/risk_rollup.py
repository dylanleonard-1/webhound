# WebHound — scanner/webhound/portfolio/risk_rollup.py
# Phase-17 Task 2/6: roll per-site risk up into portfolio-level views —
# the risk distribution, the most-vulnerable / most-changed / most-stable
# sites, and the aggregate signals the portfolio scores build on.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.portfolio.site_health import assess_site_health
from webhound.portfolio.site_registry import SiteRecord

_LEVEL_ORDER = ("critical", "high", "medium", "low", "safe")
_LEVEL_WEIGHT = {"critical": 100, "high": 70, "medium": 45,
                 "low": 20, "safe": 5}


@dataclass
class RiskRollup:
    site_count: int = 0
    risk_distribution: dict[str, int] = field(default_factory=dict)
    avg_risk_score: float = 0.0
    weighted_portfolio_risk: int = 0       # 0-100
    sites_with_compromise: int = 0
    sites_with_confirmed_risk: int = 0
    total_confirmed_risks: int = 0
    most_vulnerable: list[dict[str, Any]] = field(default_factory=list)
    most_changed: list[dict[str, Any]] = field(default_factory=list)
    most_stable: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_count": self.site_count,
            "risk_distribution": dict(self.risk_distribution),
            "avg_risk_score": round(self.avg_risk_score, 1),
            "weighted_portfolio_risk": self.weighted_portfolio_risk,
            "sites_with_compromise": self.sites_with_compromise,
            "sites_with_confirmed_risk": self.sites_with_confirmed_risk,
            "total_confirmed_risks": self.total_confirmed_risks,
            "most_vulnerable": list(self.most_vulnerable),
            "most_changed": list(self.most_changed),
            "most_stable": list(self.most_stable),
        }


def build_risk_rollup(sites: list[SiteRecord], *, top_n: int = 5) -> RiskRollup:
    """Aggregate a list of sites into a portfolio risk rollup."""
    roll = RiskRollup(site_count=len(sites))
    if not sites:
        return roll

    dist = {lvl: 0 for lvl in _LEVEL_ORDER}
    total_score = 0
    weighted_sum = 0
    for rec in sites:
        s = rec.summary
        lvl = s.risk_level if s.risk_level in dist else "safe"
        dist[lvl] += 1
        total_score += s.risk_score
        weighted_sum += _LEVEL_WEIGHT.get(lvl, 5)
        if s.has_compromise_story:
            roll.sites_with_compromise += 1
        if s.confirmed_risk_count:
            roll.sites_with_confirmed_risk += 1
            roll.total_confirmed_risks += s.confirmed_risk_count

    roll.risk_distribution = {k: v for k, v in dist.items() if v}
    roll.avg_risk_score = total_score / len(sites)
    # Weighted portfolio risk: the average site weight, nudged up when a
    # meaningful share of the portfolio is compromised (a few bad sites
    # in a big portfolio still matter).
    base = weighted_sum / len(sites)
    compromise_share = roll.sites_with_compromise / len(sites)
    roll.weighted_portfolio_risk = int(round(min(
        100, base + compromise_share * 30)))

    # Rankings.
    health = {rec.site_id: assess_site_health(rec) for rec in sites}
    by_risk = sorted(sites, key=lambda r: (
        health[r.site_id].health_score, r.summary.risk_score), reverse=True)
    roll.most_vulnerable = [
        {"site_id": r.site_id, "url": r.url,
         "risk_level": r.summary.risk_level,
         "health_score": health[r.site_id].health_score}
        for r in by_risk[:top_n]
        if health[r.site_id].health_score >= 30]

    by_change = sorted(sites, key=lambda r: r.summary.change_frequency,
                       reverse=True)
    roll.most_changed = [
        {"site_id": r.site_id, "url": r.url,
         "change_frequency": r.summary.change_frequency}
        for r in by_change[:top_n] if r.summary.change_frequency > 0]

    by_stable = sorted(sites, key=lambda r: (
        health[r.site_id].health_score, r.summary.change_frequency))
    roll.most_stable = [
        {"site_id": r.site_id, "url": r.url,
         "health_score": health[r.site_id].health_score}
        for r in by_stable[:top_n]
        if health[r.site_id].health_score < 30]

    return roll
