# WebHound — apps/api/billing/plans.py
# Plan-tier definitions. Single source of truth for limits + pricing,
# consumed by both quota enforcement (server-side) and the pricing page
# rendering (frontend imports the mirrored copy in lib/plans.ts).
#
# Stripe products (all monthly recurring):
#   WebHound Pro        — $29 / mo
#   WebHound Shield     — $79 / mo
#   WebHound Enterprise — $129 / mo
#
# When updating: also update apps/web/src/lib/plans.ts so the frontend
# pricing page stays in sync.

from __future__ import annotations

import os
from dataclasses import dataclass, field

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
    name: str                       # Display name ("Free", "Pro", "Shield")
    tagline: str
    price_usd_monthly: int          # 0 for free
    stripe_price_id_monthly: str | None

    # Hard limits
    max_websites: int
    scans_per_month: int            # Across all websites; rolling 30-day window
    scan_history_days: int          # How many days of past results are visible
    max_concurrent_scans: int       # Simultaneous in-flight scan jobs

    # Engine subset — when None, all 12 engines run. When a list, only the
    # named engines run for this tier's scans.
    engines_allowed: list[str] | None

    # Scan profile subset — tiers below Pro can't run "deep" (100 pages,
    # depth 4). Always includes "monitor" — that's the scheduler's
    # internal profile, not user-facing.
    scan_profiles_allowed: list[str]

    # Capability flags
    monitoring_enabled: bool        # Scheduled / recurring scans
    monitoring_min_frequency: str   # "manual" / "weekly" / "daily"
    exports_enabled: bool           # PDF / CSV / SARIF / JSON downloads
    alerts_enabled: bool            # Email / webhook notifications on findings
    threat_intel_external: bool     # VirusTotal / URLhaus enrichment
    team_seats: int                 # 1 = single user; >1 = team workspace
    api_access: bool                # Read-only API key access

    # Marketing copy
    features: list[PlanFeature] = field(default_factory=list)
    is_popular: bool = False
    cta_label: str = "Get started"

    # Display ordering on the pricing page (low → high)
    sort_order: int = 0


def _price(tier: str) -> str | None:
    """Read Stripe price ID for *tier* from env (STRIPE_PRICE_<TIER>_MONTHLY)."""
    return os.getenv(f"STRIPE_PRICE_{tier.upper()}_MONTHLY")


# ---------------------------------------------------------------------------
# Plan catalog — must match the 3 Stripe products in the WebHound account
# ---------------------------------------------------------------------------

PLAN_DEFINITIONS: dict[PlanTier, PlanDefinition] = {
    PlanTier.FREE: PlanDefinition(
        tier=PlanTier.FREE,
        name="Free",
        tagline="Try WebHound on one website. No card required.",
        price_usd_monthly=0,
        stripe_price_id_monthly=None,
        max_websites=1,
        scans_per_month=5,
        scan_history_days=7,
        max_concurrent_scans=1,
        engines_allowed=[
            "security_headers", "cors", "cookies", "csp",
            "secret_scanner", "form_risk", "input_analysis",
            "technology", "sensitive_paths",
        ],
        scan_profiles_allowed=["quick", "monitor"],
        monitoring_enabled=False,
        monitoring_min_frequency="manual",
        exports_enabled=False,
        alerts_enabled=False,
        threat_intel_external=False,
        team_seats=1,
        api_access=False,
        cta_label="Start free",
        sort_order=10,
        features=[
            PlanFeature("1 monitored website", True),
            PlanFeature("5 scans per month", True),
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
    PlanTier.PRO: PlanDefinition(
        tier=PlanTier.PRO,
        name="Pro",
        tagline="For solo founders and small sites.",
        price_usd_monthly=29,
        stripe_price_id_monthly=_price("pro"),
        max_websites=5,
        scans_per_month=50,
        scan_history_days=30,
        max_concurrent_scans=2,
        engines_allowed=None,
        scan_profiles_allowed=["quick", "standard", "monitor"],
        monitoring_enabled=True,
        monitoring_min_frequency="weekly",
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=False,
        team_seats=1,
        api_access=False,
        cta_label="Upgrade to Pro",
        sort_order=20,
        features=[
            PlanFeature("5 monitored websites", True),
            PlanFeature("50 scans per month", True),
            PlanFeature("30-day scan history", True),
            PlanFeature("All 12 security engines", True),
            PlanFeature("Weekly continuous monitoring", True),
            PlanFeature("PDF / CSV / SARIF / JSON exports", True),
            PlanFeature("Email alerts on new findings", True),
            PlanFeature("VirusTotal threat-intel enrichment", False),
            PlanFeature("Team seats", False),
            PlanFeature("API access", False),
        ],
    ),
    PlanTier.SHIELD: PlanDefinition(
        tier=PlanTier.SHIELD,
        name="Shield",
        tagline="For growing SaaS and busy agencies.",
        price_usd_monthly=79,
        stripe_price_id_monthly=_price("shield"),
        max_websites=25,
        scans_per_month=250,
        scan_history_days=180,
        max_concurrent_scans=5,
        engines_allowed=None,
        scan_profiles_allowed=["quick", "standard", "deep", "monitor"],
        monitoring_enabled=True,
        monitoring_min_frequency="daily",
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=True,
        team_seats=3,
        api_access=True,
        cta_label="Upgrade to Shield",
        is_popular=True,
        sort_order=30,
        features=[
            PlanFeature("25 monitored websites", True),
            PlanFeature("250 scans per month", True),
            PlanFeature("6-month scan history", True),
            PlanFeature("All 12 security engines", True),
            PlanFeature("Daily continuous monitoring", True),
            PlanFeature("All report formats + scheduled exports", True),
            PlanFeature("Email + webhook alerts", True),
            PlanFeature("VirusTotal threat-intel enrichment", True),
            PlanFeature("3 team seats", True),
            PlanFeature("Read-only API access", True),
        ],
    ),
    PlanTier.ENTERPRISE: PlanDefinition(
        tier=PlanTier.ENTERPRISE,
        name="Managed Security Review",
        tagline="Everything in Shield plus a 1-on-1 review with our team.",
        price_usd_monthly=129,
        stripe_price_id_monthly=_price("enterprise"),
        max_websites=200,
        scans_per_month=2000,
        scan_history_days=365,
        max_concurrent_scans=15,
        engines_allowed=None,
        scan_profiles_allowed=["quick", "standard", "deep", "monitor"],
        monitoring_enabled=True,
        monitoring_min_frequency="daily",
        exports_enabled=True,
        alerts_enabled=True,
        threat_intel_external=True,
        team_seats=15,
        api_access=True,
        cta_label="Get Managed Review",
        sort_order=40,
        features=[
            PlanFeature("Everything in Shield", True),
            PlanFeature("1-on-1 virtual security review", True),
            PlanFeature("Scan walkthrough session", True),
            PlanFeature("Personalized remediation recommendations", True),
            PlanFeature("Setup guidance", True),
            PlanFeature("Priority support", True),
            PlanFeature("Team / business assistance", True),
            PlanFeature("200 monitored websites", True),
            PlanFeature("2,000 scans per month", True),
            PlanFeature("Full 1-year scan history", True),
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
        "max_websites": plan.max_websites,
        "scans_per_month": plan.scans_per_month,
        "scan_history_days": plan.scan_history_days,
        "max_concurrent_scans": plan.max_concurrent_scans,
        "engines_allowed": plan.engines_allowed,
        "scan_profiles_allowed": plan.scan_profiles_allowed,
        "monitoring_enabled": plan.monitoring_enabled,
        "monitoring_min_frequency": plan.monitoring_min_frequency,
        "exports_enabled": plan.exports_enabled,
        "alerts_enabled": plan.alerts_enabled,
        "threat_intel_external": plan.threat_intel_external,
        "team_seats": plan.team_seats,
        "api_access": plan.api_access,
        "is_popular": plan.is_popular,
        "cta_label": plan.cta_label,
        "sort_order": plan.sort_order,
        "features": [{"label": f.label, "included": f.included}
                     for f in plan.features],
    }
