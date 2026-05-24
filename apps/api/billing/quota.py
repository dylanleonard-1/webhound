# WebHound — apps/api/billing/quota.py
# Tier-based quota enforcement.
#
# Every check returns None when allowed, or a QuotaViolation when not.
# Routes convert violations into HTTP 402 Payment Required responses with
# a structured body explaining the limit hit and the upgrade path.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.plans import PlanDefinition, get_plan
from apps.api.models.enums import PlanTier, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.user import User
from apps.api.models.website import Website


@dataclass(frozen=True)
class QuotaViolation:
    """Returned by check_* when the user has hit a plan limit."""
    limit_name: str           # e.g. "max_websites", "scans_per_month"
    limit_value: int          # The numeric cap from their plan
    current_value: int        # What they're currently using
    plan: PlanTier            # Their current plan
    upgrade_to: PlanTier | None  # Recommended next plan, or None if at top
    message: str              # Human-readable explanation


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _next_tier(current: PlanTier) -> PlanTier | None:
    order = [PlanTier.FREE, PlanTier.STARTER, PlanTier.PRO, PlanTier.ENTERPRISE]
    try:
        idx = order.index(current)
    except ValueError:
        return PlanTier.STARTER
    return order[idx + 1] if idx + 1 < len(order) else None


def _plan_of(user: User) -> PlanDefinition:
    return get_plan(user.plan)


# ---------------------------------------------------------------------------
# Quota checks
# ---------------------------------------------------------------------------


async def check_website_quota(
    db: AsyncSession, user: User,
) -> QuotaViolation | None:
    """Enforce max_websites — called before creating a new Website row."""
    plan = _plan_of(user)
    count = await db.scalar(
        sa.select(sa.func.count())
        .select_from(Website)
        .where(Website.user_id == user.id)
    ) or 0
    if count >= plan.max_websites:
        return QuotaViolation(
            limit_name="max_websites",
            limit_value=plan.max_websites,
            current_value=count,
            plan=user.plan,
            upgrade_to=_next_tier(user.plan),
            message=(
                f"Your {plan.name} plan includes {plan.max_websites} "
                f"website{'s' if plan.max_websites != 1 else ''}. "
                "Upgrade to monitor more sites."
            ),
        )
    return None


async def check_scan_quota(
    db: AsyncSession, user: User,
) -> QuotaViolation | None:
    """Enforce scans_per_month — called before queueing a new ScanJob.

    Rolling 30-day window, not calendar month — matches the way usage caps
    work on most modern SaaS billing (Stripe metered, Vercel, etc).
    """
    plan = _plan_of(user)
    window_start = datetime.now(timezone.utc) - timedelta(days=30)
    count = await db.scalar(
        sa.select(sa.func.count())
        .select_from(ScanJob)
        .where(ScanJob.user_id == user.id)
        .where(ScanJob.created_at >= window_start)
    ) or 0
    if count >= plan.scans_per_month:
        return QuotaViolation(
            limit_name="scans_per_month",
            limit_value=plan.scans_per_month,
            current_value=count,
            plan=user.plan,
            upgrade_to=_next_tier(user.plan),
            message=(
                f"Your {plan.name} plan includes {plan.scans_per_month} "
                "scans per 30 days. You've used all of them. "
                "Upgrade for more scans or wait for the window to roll over."
            ),
        )
    return None


async def check_concurrent_scan_quota(
    db: AsyncSession, user: User,
) -> QuotaViolation | None:
    """Enforce max_concurrent_scans — called before queueing a new ScanJob."""
    plan = _plan_of(user)
    active = {ScanStatus.QUEUED, ScanStatus.RUNNING}
    count = await db.scalar(
        sa.select(sa.func.count())
        .select_from(ScanJob)
        .where(ScanJob.user_id == user.id)
        .where(ScanJob.status.in_(active))
    ) or 0
    if count >= plan.max_concurrent_scans:
        return QuotaViolation(
            limit_name="max_concurrent_scans",
            limit_value=plan.max_concurrent_scans,
            current_value=count,
            plan=user.plan,
            upgrade_to=_next_tier(user.plan),
            message=(
                f"Your {plan.name} plan allows "
                f"{plan.max_concurrent_scans} scan"
                f"{'s' if plan.max_concurrent_scans != 1 else ''} "
                "running at once. Wait for an in-flight scan to "
                "finish, or upgrade."
            ),
        )
    return None


def check_engines_allowed(
    user: User, requested_engines: list[str] | None = None,
) -> tuple[list[str] | None, QuotaViolation | None]:
    """Return (engines_to_run, violation).

    Free tier limits which engines run. If requested_engines is None,
    return the tier's allowed list (or None = all).
    """
    plan = _plan_of(user)
    if plan.engines_allowed is None:
        return requested_engines, None
    if requested_engines is None:
        return plan.engines_allowed, None
    # Drop any engines the user can't access. Don't 402 — just silently
    # restrict, since most callers don't explicitly select engines.
    allowed_set = set(plan.engines_allowed)
    filtered = [e for e in requested_engines if e in allowed_set]
    return filtered, None


def check_monitoring_allowed(user: User) -> QuotaViolation | None:
    """Enforce monitoring_enabled — called from create-scan-schedule."""
    plan = _plan_of(user)
    if plan.monitoring_enabled:
        return None
    return QuotaViolation(
        limit_name="monitoring_enabled",
        limit_value=0, current_value=1,
        plan=user.plan,
        upgrade_to=_next_tier(user.plan),
        message=(
            "Continuous monitoring (scheduled scans) requires a paid "
            "plan. Free runs scans on demand only."
        ),
    )


def check_export_allowed(user: User) -> QuotaViolation | None:
    """Enforce exports_enabled — called from /reports/{fmt} download route."""
    plan = _plan_of(user)
    if plan.exports_enabled:
        return None
    return QuotaViolation(
        limit_name="exports_enabled",
        limit_value=0, current_value=1,
        plan=user.plan,
        upgrade_to=_next_tier(user.plan),
        message=(
            "Report downloads (PDF, CSV, SARIF, JSON, Markdown) require "
            "a paid plan. Upgrade to share results with your team."
        ),
    )


def check_alerts_allowed(user: User) -> QuotaViolation | None:
    """Enforce alerts_enabled — called from notification settings + webhook setup."""
    plan = _plan_of(user)
    if plan.alerts_enabled:
        return None
    return QuotaViolation(
        limit_name="alerts_enabled",
        limit_value=0, current_value=1,
        plan=user.plan,
        upgrade_to=_next_tier(user.plan),
        message=(
            "Email and webhook alerts require a paid plan. Free plan "
            "still shows findings in the dashboard."
        ),
    )


# ---------------------------------------------------------------------------
# HTTP-friendly helpers
# ---------------------------------------------------------------------------


def violation_to_dict(v: QuotaViolation) -> dict:
    """Serialise a QuotaViolation into a 402 response body."""
    return {
        "error": "quota_exceeded",
        "limit_name": v.limit_name,
        "limit_value": v.limit_value,
        "current_value": v.current_value,
        "current_plan": v.plan.value,
        "upgrade_to": v.upgrade_to.value if v.upgrade_to else None,
        "message": v.message,
    }
