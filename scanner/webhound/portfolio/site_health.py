# WebHound — scanner/webhound/portfolio/site_health.py
# Phase-17: per-site health — the single status a portfolio dashboard
# shows per row. Combines risk level, monitoring freshness, stability
# (change churn), and open alerts into one health verdict + score.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from webhound.portfolio.site_registry import SiteRecord


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs_attention"
    AT_RISK = "at_risk"
    CRITICAL = "critical"
    UNMONITORED = "unmonitored"

    @property
    def rank(self) -> int:
        return {"healthy": 0, "needs_attention": 1, "at_risk": 2,
                "critical": 3, "unmonitored": 4}[self.value]


# risk_level → base health contribution (0 best, 100 worst).
_RISK_BASE = {"safe": 5, "low": 20, "medium": 45, "high": 70, "critical": 95}


@dataclass
class SiteHealth:
    site_id: str
    url: str
    status: HealthStatus
    health_score: int                  # 0 (perfect) .. 100 (worst)
    risk_level: str
    reasons: list[str]

    @property
    def is_healthy(self) -> bool:
        return self.status == HealthStatus.HEALTHY

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "url": self.url,
            "status": self.status.value,
            "health_score": self.health_score,
            "risk_level": self.risk_level,
            "reasons": list(self.reasons),
        }


def assess_site_health(record: SiteRecord) -> SiteHealth:
    """Score one site's health (0 best → 100 worst) + a status band."""
    s = record.summary
    reasons: list[str] = []

    # Unmonitored: never scanned.
    if not s.last_scan_at and s.scan_count == 0:
        return SiteHealth(
            site_id=record.site_id, url=record.url,
            status=HealthStatus.UNMONITORED, health_score=100,
            risk_level=s.risk_level,
            reasons=["site has not been scanned yet"])

    score = _RISK_BASE.get(s.risk_level, 45)
    reasons.append(f"risk level: {s.risk_level}")

    # Active compromise indicator dominates.
    if s.has_compromise_story or any(
            t in ("possible_skimmer", "possible_website_compromise",
                  "possible_compromise")
            for t in s.threat_correlation_types):
        score = max(score, 90)
        reasons.append("active compromise/skimmer indicator")

    # Confirmed risks weigh heavily.
    if s.confirmed_risk_count:
        score = min(100, score + 5 * s.confirmed_risk_count)
        reasons.append(f"{s.confirmed_risk_count} confirmed risk(s)")

    # Open alerts add pressure.
    if s.open_alert_count:
        score = min(100, score + 3 * s.open_alert_count)
        reasons.append(f"{s.open_alert_count} open alert(s)")

    # High change churn reduces stability.
    if s.change_frequency >= 3:
        score = min(100, score + 5)
        reasons.append("frequent changes (low stability)")

    score = max(0, min(100, score))
    if score >= 85:
        status = HealthStatus.CRITICAL
    elif score >= 55:
        status = HealthStatus.AT_RISK
    elif score >= 30:
        status = HealthStatus.NEEDS_ATTENTION
    else:
        status = HealthStatus.HEALTHY

    return SiteHealth(
        site_id=record.site_id, url=record.url, status=status,
        health_score=score, risk_level=s.risk_level, reasons=reasons)
