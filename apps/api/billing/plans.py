# WebHound — apps/api/billing/plans.py
# Plan-tier definitions. Single source of truth for limits + pricing,
# consumed by both quota enforcement (server-side) and the pricing page
# rendering (frontend imports the mirrored copy in lib/plans.ts).
#
# When updating: also update apps/web/src/lib/plans.ts so the frontend
# pricing page stays in sync.

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from apps.api.models.enums import PlanTier


@dataclass(frozen=True)
class PlanFeature:
    """A single capability flag rendered on the pricing page."""
    label: str
    included: bool


@dataclass(frozen=True)
class PlanDefinition:
    """One plan tier — limits, pricing, and capability flags."""

    tier: PlanTier
    name: str                       # Display name ("Free", "Starter", "Pro")
    tagline: str
    price_usd_monthly: int          # 0 for free / enterprise (contact-sales)
    price_usd_yearly: int           # 0 for free; yearly is monthly * 10 for paid
    stripe_price_id_monthly: str | None
    stripe_price_id_yearly: str | None

    # Hard limits
    max_websites: int
    scans_per_month: int            # Across all websites; rolling 30-day window
    scan_history_days: int          # How many days of past results are visible
    max_concurrent_scans: int       # Simultaneous in-flight scan jobs

    # Engine subset — when None, all 12 engines run. When a list, only the
    # named engines run for this tier's scans.
    engines_allowed: list[str] | None

    # Capability flags
    monitoring_enabled: bool        # Scheduled / recurring scans
    exports_enabled: bool           # PDF / CSV / SARIF / JSON downloads
    alerts_enabled: bool            # Email / webhook notifications on findings
    threat_intel_external: bool     # VirusTotal / URLhaus enrichment
    team_seats: int                 # 1 = single user; >1 = team workspace

    # Marketing copy
    features: list[PlanFeature] = field(default_factory=list)
    is_popular: bool = False
    cta_label: str = "Get started"

    # Display ordering on the pricing page (low → high)
    sort_order: int = 0


# ---------------------------------------------------------------------------
# Stripe price IDs are read from env so test / live keys can be swapped
# without touching code. Env var names: STRIPE_PRICE_<TIER>_<CADENCE>.
# ---------------------------------------------------------------------------

def _price(tier: str, cadence: Literal["monthly", "yearly"]) -> str | None:
    return os.getenv(f"STRIPE_PRICE_{tier.upper()}_{cadence.upper()}")


# ---------------------------------------------------------------------------
# Plan catalog
# ---------------------------------------------------------------------------

PLAN_DEFINITIONS: dict[PlanTier, PlanDefinition] = {
    PlanTier.FREE: PlanDefinition(
        tier=PlanTier.FREE,
        name="Free",
        tagline="Try WebHound on a single site.",
        price_usd_monthly=0,
        price_usd_yearly=0,
        stripe_price_id_monthly=None,
        stripe_price_id_yearly=None,
        max_websites=1,
        scans_per_month=5,
        scan_history_days=7,
        max_concurrent_scans=1,
        engines_allowed=[
            "security_headers", "cors", "cookies", "csp",
            "secret_scanner", "form_risk", "input_analysis",
            "technology", "sensitive_paths",
        ],
        monitoring_enabled=False,
        exports_enabled=False,
        alerts_enabled=False,
        threat_intel_external=False,
        team_seats=1,
        cta_label="Start free",
        sort_order=10,
        features=[
            PlanFeature("1 monitored website", True),
            PlanFeature("5 scans / month", True),
            PlanFeature("7-day scan history", True),
            PlanFeature("9 of 12 security engines", True),
            PlanFeature("Plain-English findings", True),
            PlanFeature("Continuous monitoring", False),
            PlanFeature("PDF / CSV / SARIF exports", False),
            PlanFeature("Email + webhook alerts", False),
            PlanFeature("VirusTotal threat-intel enrichment", False),
            PlanFeature("API access", False),
        ],
    ),
    PlanTier.STARTER: PlanDefinition(
        tier=PlanTier.STARTER,
        name="Starter",
        tagline="For freelancers and small teams.",
        price_usd_monthly=19,
        price_usd_yearly=190,
        stripe_price_id_monthly=_price("starter", "monthly"),
        stripe_price_id_yearly=_price("starter", "yearly"),
        max_websites=5,
        scans_per_month=100,
        scan_history_days=90,
        max_concurrent_scans=2,
        engines_allowed=None,
        monitoring_enabled=True,
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=False,
        team_seats=1,
        cta_label="Upgrade to Starter",
        sort_order=20,
        features=[
            PlanFeature("5 monitored websites", True),
            PlanFeature("100 scans / month", True),
            PlanFeature("90-day scan history", True),
            PlanFeature("All 12 security engines", True),
            PlanFeature("Continuous monitoring (weekly)", True),
            PlanFeature("PDF / CSV / SARIF exports", True),
            PlanFeature("Email alerts on new findings", True),
            PlanFeature("VirusTotal threat-intel enrichment", False),
            PlanFeature("Team seats", False),
            PlanFeature("API access", False),
        ],
    ),
    PlanTier.PRO: PlanDefinition(
        tier=PlanTier.PRO,
        name="Pro",
        tagline="For agencies and growing SaaS.",
        price_usd_monthly=49,
        price_usd_yearly=490,
        stripe_price_id_monthly=_price("pro", "monthly"),
        stripe_price_id_yearly=_price("pro", "yearly"),
        max_websites=25,
        scans_per_month=500,
        scan_history_days=365,
        max_concurrent_scans=5,
        engines_allowed=None,
        monitoring_enabled=True,
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=True,
        team_seats=5,
        cta_label="Upgrade to Pro",
        is_popular=True,
        sort_order=30,
        features=[
            PlanFeature("25 monitored websites", True),
            PlanFeature("500 scans / month", True),
            PlanFeature("Full 1-year scan history", True),
            PlanFeature("All 12 security engines", True),
            PlanFeature("Continuous monitoring (daily)", True),
            PlanFeature("PDF / CSV / SARIF exports", True),
            PlanFeature("Email + webhook alerts", True),
            PlanFeature("VirusTotal threat-intel enrichment", True),
            PlanFeature("5 team seats", True),
            PlanFeature("API access (read-only)", True),
        ],
    ),
    PlanTier.ENTERPRISE: PlanDefinition(
        tier=PlanTier.ENTERPRISE,
        name="Enterprise",
        tagline="Custom limits, SSO, and SOC 2 evidence support.",
        price_usd_monthly=0,           # Contact sales
        price_usd_yearly=0,
        stripe_price_id_monthly=None,
        stripe_price_id_yearly=None,
        max_websites=10_000,
        scans_per_month=100_000,
        scan_history_days=3650,
        max_concurrent_scans=20,
        engines_allowed=None,
        monitoring_enabled=True,
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=True,
        team_seats=999,
        cta_label="Contact sales",
        sort_order=40,
        features=[
            PlanFeature("Unlimited websites", True),
            PlanFeature("Unlimited scans", True),
            PlanFeature("Custom scan-history retention", True),
            PlanFeature("All 12 security engines + custom rules", True),
            PlanFeature("SSO (SAML / OIDC)", True),
            PlanFeature("SOC 2 evidence collection", True),
            PlanFeature("Dedicated success manager", True),
            PlanFeature("99.9% uptime SLA", True),
            PlanFeature("Custom integrations (Slack, Jira, PagerDuty)", True),
            PlanFeature("On-prem deployment available", True),
        ],
    ),
}


def get_plan(tier: PlanTier | str) -> PlanDefinition:
    """Return the PlanDefinition for *tier*. Raises KeyError for unknown."""
    if isinstance(tier, str):
        tier = PlanTier(tier)
    return PLAN_DEFINITIONS[tier]


def plan_for_route_display(tier: PlanTier | str) -> dict:
    """Return a dict suitable for serialising into an API response."""
    plan = get_plan(tier)
    return {
        "tier": plan.tier.value,
        "name": plan.name,
        "tagline": plan.tagline,
        "price_usd_monthly": plan.price_usd_monthly,
        "price_usd_yearly": plan.price_usd_yearly,
        "max_websites": plan.max_websites,
        "scans_per_month": plan.scans_per_month,
        "scan_history_days": plan.scan_history_days,
        "max_concurrent_scans": plan.max_concurrent_scans,
        "engines_allowed": plan.engines_allowed,
        "monitoring_enabled": plan.monitoring_enabled,
        "exports_enabled": plan.exports_enabled,
        "alerts_enabled": plan.alerts_enabled,
        "threat_intel_external": plan.threat_intel_external,
        "team_seats": plan.team_seats,
        "is_popular": plan.is_popular,
        "cta_label": plan.cta_label,
        "sort_order": plan.sort_order,
        "features": [{"label": f.label, "included": f.included}
                     for f in plan.features],
    }
