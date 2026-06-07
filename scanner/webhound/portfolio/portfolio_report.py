# WebHound — scanner/webhound/portfolio/portfolio_report.py
# Phase-17 Task 6/7/8: the portfolio dashboard data + executive report +
# white-label config. The top-level command center that ties registry,
# scores, rollup, and cross-site alerts into one customer/agency view.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.portfolio.portfolio_alerts import (
    compare_sites,
    detect_cross_site_alerts,
)
from webhound.portfolio.portfolio_score import compute_portfolio_scores
from webhound.portfolio.risk_rollup import build_risk_rollup
from webhound.portfolio.site_health import assess_site_health
from webhound.portfolio.site_registry import SiteRegistry


# ---------------------------------------------------------------------------
# White-label config (Task 7)
# ---------------------------------------------------------------------------


@dataclass
class BrandingConfig:
    """Agency white-label configuration. Drives branded reports/exports
    and client-specific views — the architecture, not the rendering."""

    agency_name: str = "WebHound"
    logo_url: str | None = None
    primary_color: str = "#0E7C5A"
    report_footer: str = ""
    support_email: str | None = None
    hide_webhound_branding: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "agency_name": self.agency_name,
            "logo_url": self.logo_url,
            "primary_color": self.primary_color,
            "report_footer": self.report_footer,
            "support_email": self.support_email,
            "hide_webhound_branding": self.hide_webhound_branding,
        }


# ---------------------------------------------------------------------------
# Dashboard data (Task 6)
# ---------------------------------------------------------------------------


def build_dashboard_data(registry: SiteRegistry) -> dict[str, Any]:
    """The portfolio dashboard payload: sites monitored, risk + alert
    distribution, and the most-vulnerable / most-changed / most-stable
    rankings."""
    sites = registry.all()
    rollup = build_risk_rollup(sites)
    scores = compute_portfolio_scores(sites)
    alerts = detect_cross_site_alerts(sites)
    health = [assess_site_health(r) for r in sites]

    alert_dist: dict[str, int] = {}
    for a in alerts:
        alert_dist[a.severity.value] = alert_dist.get(a.severity.value, 0) + 1
    health_dist: dict[str, int] = {}
    for h in health:
        health_dist[h.status.value] = health_dist.get(h.status.value, 0) + 1

    return {
        "sites_monitored": registry.count,
        "scores": scores.to_dict(),
        "risk_distribution": rollup.risk_distribution,
        "health_distribution": health_dist,
        "alert_distribution": alert_dist,
        "cross_site_alert_count": len(alerts),
        "most_vulnerable_sites": rollup.most_vulnerable,
        "most_changed_sites": rollup.most_changed,
        "most_stable_sites": rollup.most_stable,
    }


# ---------------------------------------------------------------------------
# Executive portfolio report (Task 8)
# ---------------------------------------------------------------------------


@dataclass
class ExecutivePortfolioReport:
    branding: dict[str, Any]
    summary: dict[str, Any]
    top_risks: list[dict[str, Any]] = field(default_factory=list)
    top_changes: list[dict[str, Any]] = field(default_factory=list)
    portfolio_health: dict[str, Any] = field(default_factory=dict)
    trend: dict[str, Any] = field(default_factory=dict)
    narrative: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "branding": self.branding,
            "summary": self.summary,
            "top_risks": self.top_risks,
            "top_changes": self.top_changes,
            "portfolio_health": self.portfolio_health,
            "trend": self.trend,
            "narrative": self.narrative,
        }


def build_executive_report(
    registry: SiteRegistry,
    *,
    branding: BrandingConfig | None = None,
    previous_scores: dict[str, Any] | None = None,
) -> ExecutivePortfolioReport:
    """Build the executive portfolio report (Task 8)."""
    branding = branding or BrandingConfig()
    sites = registry.all()
    scores = compute_portfolio_scores(sites)
    rollup = build_risk_rollup(sites)
    alerts = detect_cross_site_alerts(sites)

    summary = {
        "sites_monitored": registry.count,
        "portfolio_risk_score": scores.risk_score,
        "portfolio_health_score": scores.health_score,
        "risk_band": scores.risk_band,
        "sites_with_compromise": rollup.sites_with_compromise,
        "cross_site_alerts": len(alerts),
    }

    top_risks = [a.to_dict() for a in alerts[:5]] or rollup.most_vulnerable[:5]
    top_changes = rollup.most_changed[:5]

    portfolio_health = {
        "health_score": scores.health_score,
        "health_band": scores.health_band,
        "monitoring_score": scores.monitoring_score,
        "stability_score": scores.stability_score,
    }

    # Trend vs a previous portfolio snapshot (Task 8 trend analysis).
    trend: dict[str, Any] = {}
    if previous_scores:
        prev_risk = previous_scores.get("portfolio_risk_score", scores.risk_score)
        delta = scores.risk_score - prev_risk
        trend = {
            "risk_change": delta,
            "direction": ("increased" if delta > 2 else
                          "decreased" if delta < -2 else "stable"),
            "previous_risk_score": prev_risk,
            "current_risk_score": scores.risk_score,
        }

    # Plain-language narrative.
    n = registry.count
    if n == 0:
        narrative = "No sites are being monitored yet."
    else:
        bits = [f"{n} site(s) monitored.",
                f"Portfolio health is {scores.health_band} "
                f"({scores.health_score}/100)."]
        if rollup.sites_with_compromise:
            bits.append(f"{rollup.sites_with_compromise} site(s) show "
                        "compromise indicators and need immediate attention.")
        if alerts:
            bits.append(f"{len(alerts)} cross-site risk(s) affect multiple "
                        "sites at once.")
        if trend.get("direction") == "increased":
            bits.append("Overall portfolio risk increased since the last "
                        "report.")
        elif trend.get("direction") == "decreased":
            bits.append("Overall portfolio risk decreased since the last "
                        "report — good progress.")
        narrative = " ".join(bits)

    return ExecutivePortfolioReport(
        branding=branding.to_dict(), summary=summary,
        top_risks=top_risks, top_changes=top_changes,
        portfolio_health=portfolio_health, trend=trend, narrative=narrative)
