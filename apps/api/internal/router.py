# WebHound — apps/api/internal/router.py
# Internal /control command-center APIs (RBAC-gated). Phase 1: identity + the
# Global Command Center metrics aggregator wired to real live data.
#
# Every section is computed defensively so one failing query degrades a single
# tile rather than 500-ing the whole dashboard.

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

import redis.asyncio as aioredis
import sqlalchemy as sa
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.plans import PLAN_DEFINITIONS
from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.internal.rbac import require_admin, role_of
from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.enums import AdminRole, PlanTier, ScanStatus, SubscriptionStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.subscription import Subscription
from apps.api.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

_AnyAdmin = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_DB = Annotated[AsyncSession, Depends(get_db)]

_ACTIVE_SUB = (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING)


@router.get("/platform-access")
async def internal_platform_access(admin: _AnyAdmin, db: _DB) -> dict:
    """Platform Access Framework admin view: configured providers, the current
    scanner egress IPs, verification success rate, and the most-common detected
    providers / failures / blocks — aggregated from the platform.* audit trail."""
    from apps.api.config import scanner_outbound_ips
    from apps.api.services import platform_access as pa
    rows = (await db.execute(
        select(AdminAuditLog)
        .where(AdminAuditLog.action.like("platform.%"))
        .order_by(AdminAuditLog.created_at.desc())
        .limit(5000)
    )).scalars().all()
    events = [{"event_type": r.action, "provider": (r.detail or {}).get("provider")}
              for r in rows]
    return pa.build_admin_stats(
        events, providers=pa.registry_provider_summaries(),
        scanner_ips=scanner_outbound_ips())


@router.get("/me")
async def internal_me(admin: _AnyAdmin) -> dict:
    """Identity + role for the authenticated staff member (gates the UI)."""
    role = role_of(admin)
    return {
        "id": str(admin.id),
        "email": admin.email,
        "full_name": admin.full_name,
        "role": role.value,
        "is_super_admin": role == AdminRole.SUPER_ADMIN,
    }


def _pct_delta(current: float | int, prior: float | int) -> float | None:
    """% change current vs prior. None when prior is 0 (no meaningful baseline)
    so the UI can render a neutral 'new' state instead of a fake 'infinity'."""
    if prior is None or prior == 0:
        return None
    return round(100 * (current - prior) / prior, 1)


async def _scan_metrics(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    prior_window_start = now - timedelta(hours=48)
    rows = await db.execute(select(ScanJob.status, func.count()).group_by(ScanJob.status))
    by_status = {str(getattr(s, "value", s)): n for s, n in rows.all()}
    completed_24h = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .where(ScanJob.status == ScanStatus.COMPLETED, ScanJob.created_at >= since)
    ) or 0
    failed_24h = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .where(ScanJob.status == ScanStatus.FAILED, ScanJob.created_at >= since)
    ) or 0
    # Prior 24h window (48h ago → 24h ago) for the trend arrow.
    completed_prior = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .where(ScanJob.status == ScanStatus.COMPLETED,
               ScanJob.created_at >= prior_window_start,
               ScanJob.created_at < since)
    ) or 0
    failed_prior = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .where(ScanJob.status == ScanStatus.FAILED,
               ScanJob.created_at >= prior_window_start,
               ScanJob.created_at < since)
    ) or 0
    avg_secs = await db.scalar(
        select(func.avg(func.extract("epoch", ScanJob.completed_at - ScanJob.created_at)))
        .where(ScanJob.status == ScanStatus.COMPLETED, ScanJob.completed_at.is_not(None),
               ScanJob.created_at >= since)
    )
    return {
        "queued": int(by_status.get("queued", 0)),
        "running": int(by_status.get("running", 0)),
        "failed_24h": int(failed_24h),
        "completed_24h": int(completed_24h),
        "total": int(sum(by_status.values())),
        "avg_duration_s": round(float(avg_secs), 1) if avg_secs is not None else None,
        # Trend deltas — % change vs the previous matching window.
        "completed_24h_delta_pct": _pct_delta(completed_24h, completed_prior),
        "failed_24h_delta_pct": _pct_delta(failed_24h, failed_prior),
    }


async def _user_metrics(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    week = now - timedelta(days=7)
    prior_week = now - timedelta(days=14)
    total = await db.scalar(select(func.count()).select_from(User)) or 0
    paid = await db.scalar(
        select(func.count()).select_from(User).where(User.plan != PlanTier.FREE)
    ) or 0
    new_7d = await db.scalar(
        select(func.count()).select_from(User).where(User.created_at >= week)
    ) or 0
    # Prior 7d window — for the new-users trend.
    new_prior_7d = await db.scalar(
        select(func.count()).select_from(User).where(
            User.created_at >= prior_week, User.created_at < week,
        )
    ) or 0
    return {
        "total": int(total), "paid": int(paid), "new_7d": int(new_7d),
        "new_7d_delta_pct": _pct_delta(new_7d, new_prior_7d),
    }


async def _billing_metrics(db: AsyncSession) -> dict:
    rows = await db.execute(
        select(Subscription.plan, func.count())
        .where(Subscription.status.in_(_ACTIVE_SUB))
        .group_by(Subscription.plan)
    )
    active = 0
    mrr = 0
    for plan, n in rows.all():
        active += int(n)
        tier = plan if isinstance(plan, PlanTier) else PlanTier(str(getattr(plan, "value", plan)))
        price = PLAN_DEFINITIONS.get(tier).price_usd_monthly if PLAN_DEFINITIONS.get(tier) else 0
        mrr += price * int(n)
    return {"active_subscriptions": active, "mrr_usd": mrr, "arr_usd": mrr * 12}


async def _infra_metrics(db: AsyncSession) -> dict:
    settings = get_settings()
    db_ok = redis_ok = False
    queue_depth = None
    worker = "unknown"
    try:
        await db.execute(sa.text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        pass
    try:
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2, decode_responses=True)
        await r.ping()
        redis_ok = True
        try:
            queue_depth = int(await r.llen("celery"))
        except Exception:  # noqa: BLE001
            pass
        # Worker liveness: the beat heartbeat task stamps this key every 5 min.
        try:
            beat = await r.get("webhound:worker:heartbeat")
            if beat:
                age = (datetime.now(timezone.utc).timestamp() - float(beat))
                worker = "ok" if age < 600 else "stale"
        except Exception:  # noqa: BLE001
            pass
        await r.aclose()
    except Exception:  # noqa: BLE001
        pass
    # Roll the four tiles into a single operational status the header pill
    # can display. Maintenance + worker stale + Redis down each degrade the
    # overall posture, but Stripe being unconfigured isn't a SOC-blocker.
    from apps.api.services.maintenance import is_active as _maint_active
    try:
        maintenance = await _maint_active()
    except Exception:  # noqa: BLE001
        maintenance = False

    if maintenance:
        overall = "maintenance"
    elif not db_ok or not redis_ok:
        overall = "offline"
    elif worker == "stale" or worker == "unknown":
        overall = "degraded"
    else:
        overall = "operational"
    return {
        "database": "ok" if db_ok else "down",
        "redis": "ok" if redis_ok else "down",
        "queue_depth": queue_depth,
        "worker": worker,
        "stripe_configured": bool(settings.stripe_secret_key and settings.stripe_webhook_secret),
        "maintenance": maintenance,
        "overall": overall,
    }


async def _recent_activity(db: AsyncSession) -> list[dict]:
    rows = await db.execute(
        select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(20)
    )
    return [
        {
            "id": str(a.id),
            "actor": a.actor_email,
            "action": a.action,
            "target": f"{a.target_type}:{a.target_id}" if a.target_type else None,
            "at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows.scalars().all()
    ]


@router.get("/command-center")
async def command_center(admin: _AnyAdmin, db: _DB) -> dict:
    """Global Command Center — aggregated live operational metrics."""
    out: dict = {"generated_at": datetime.now(timezone.utc).isoformat()}
    for key, fn in (
        ("scans", _scan_metrics),
        ("users", _user_metrics),
        ("billing", _billing_metrics),
        ("infra", _infra_metrics),
    ):
        try:
            out[key] = await fn(db)
        except Exception:  # noqa: BLE001 — degrade one tile, not the dashboard
            logger.exception("command-center: %s metric failed", key)
            out[key] = {"error": "unavailable"}
    try:
        out["activity"] = await _recent_activity(db)
    except Exception:  # noqa: BLE001
        out["activity"] = []
    # Top incident drives the dashboard banner — degrade silently if the
    # incidents service is unavailable.
    try:
        from apps.api.services import incidents as inc_svc
        out["incidents"] = await inc_svc.summary(db)
    except Exception:  # noqa: BLE001
        out["incidents"] = {"active": 0, "by_status": {}, "by_severity": {},
                            "breached": 0, "top": None}
    return out
