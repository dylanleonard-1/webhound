# WebHound — apps/api/services/customers.py
# Customer-ops lifecycle (search, detail aggregates, suspend, force-logout,
# plan override, internal notes). All mutators add/flush within the caller's
# transaction; the caller commits + records audit.

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import PlanTier, ScanStatus, SubscriptionStatus
from apps.api.models.internal_note import InternalNote
from apps.api.models.scan_job import ScanJob
from apps.api.models.subscription import Subscription
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import denylist_clear, denylist_user

_NOTE_TARGET_USER = "user"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def search(
    db: AsyncSession, *,
    q: str | None = None,
    plan: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[User], int]:
    """status: 'active' | 'suspended' | 'staff' | None (all)."""
    base = select(User)
    count_base = select(func.count()).select_from(User)
    conds = []
    if q:
        like = f"%{q.lower()}%"
        conds.append(sa.or_(
            sa.func.lower(User.email).like(like),
            sa.func.lower(sa.func.coalesce(User.full_name, "")).like(like),
            sa.func.lower(sa.func.coalesce(User.company_name, "")).like(like),
        ))
    if plan:
        conds.append(User.plan == plan)
    if status == "active":
        conds.append(User.is_active.is_(True))
        conds.append(User.banned_at.is_(None))
    elif status == "suspended":
        conds.append(sa.or_(User.is_active.is_(False), User.banned_at.is_not(None)))
    elif status == "staff":
        conds.append(User.admin_role != "none")
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


async def detail(db: AsyncSession, user_id: uuid.UUID) -> dict | None:
    user = await db.get(User, user_id)
    if user is None:
        return None
    website_count = await db.scalar(
        select(func.count()).select_from(Website).where(Website.user_id == user_id)
    ) or 0
    scan_count = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id)
    ) or 0
    last_scan_at = await db.scalar(
        select(func.max(ScanJob.created_at))
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id)
    )
    failed_30d = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id,
               ScanJob.status == ScanStatus.FAILED,
               ScanJob.created_at >= _now() - timedelta(days=30))
    ) or 0
    sub_rows = await db.scalars(
        select(Subscription).where(Subscription.user_id == user_id)
        .order_by(Subscription.created_at.desc())
    )
    subs = []
    for s in sub_rows.all():
        subs.append({
            "id": str(s.id),
            "stripe_subscription_id": s.stripe_subscription_id,
            "plan": s.plan.value if hasattr(s.plan, "value") else str(s.plan),
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "current_period_end": s.current_period_end.isoformat() if s.current_period_end else None,
            "cancel_at_period_end": s.cancel_at_period_end,
            "canceled_at": s.canceled_at.isoformat() if s.canceled_at else None,
        })
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "company_name": user.company_name,
        "plan": user.plan.value if hasattr(user.plan, "value") else str(user.plan),
        "is_active": user.is_active,
        "is_admin": user.is_admin,
        "admin_role": user.admin_role,
        "email_verified": user.email_verified,
        "oauth_provider": user.oauth_provider,
        "stripe_customer_id": user.stripe_customer_id,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "banned_at": user.banned_at.isoformat() if user.banned_at else None,
        "banned_reason": user.banned_reason,
        "websites": int(website_count),
        "scans": int(scan_count),
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
        "failed_30d": int(failed_30d),
        "subscriptions": subs,
    }


async def suspend(db: AsyncSession, user: User, *, reason: str | None) -> User:
    user.is_active = False
    user.banned_at = _now()
    user.banned_reason = reason
    await db.flush()
    await denylist_user(user.id)   # force-logout: no Redis = best-effort
    return user


async def reactivate(db: AsyncSession, user: User) -> User:
    user.is_active = True
    user.banned_at = None
    user.banned_reason = None
    await db.flush()
    await denylist_clear(user.id)
    return user


async def force_logout(user: User) -> None:
    """No DB write — just revoke all sessions via the Redis denylist."""
    await denylist_user(user.id)


async def change_plan(db: AsyncSession, user: User, plan: PlanTier) -> User:
    user.plan = plan
    await db.flush()
    return user


# --- Internal notes ---------------------------------------------------------


async def add_note(db: AsyncSession, user_id: uuid.UUID, *, body: str,
                   author_email: str | None) -> InternalNote:
    note = InternalNote(target_type=_NOTE_TARGET_USER, target_id=str(user_id),
                        body=body, author_email=author_email)
    db.add(note)
    await db.flush()
    return note


async def list_notes(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    rows = await db.scalars(
        select(InternalNote)
        .where(InternalNote.target_type == _NOTE_TARGET_USER,
               InternalNote.target_id == str(user_id))
        .order_by(InternalNote.created_at.desc())
    )
    return [
        {
            "id": str(n.id),
            "author": n.author_email,
            "body": n.body,
            "at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in rows.all()
    ]


async def delete_note(db: AsyncSession, note_id: uuid.UUID) -> bool:
    note = await db.get(InternalNote, note_id)
    if note is None:
        return False
    await db.delete(note)
    await db.flush()
    return True


# Convenience: count active+trialing subs (used by infra metrics consumers).
_ACTIVE_SUB = (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING)
