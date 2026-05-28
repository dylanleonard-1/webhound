# WebHound — apps/api/services/team.py
# Internal team/staff lifecycle: role management (SUPER_ADMIN only) and
# session monitoring (active denylist entries + recent staff logins).

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.security import _denylist_key  # type: ignore[attr-defined]


VALID_ROLES = tuple(r.value for r in AdminRole)


async def list_staff(db: AsyncSession) -> list[dict]:
    """Every account with a non-`none` admin_role, ordered by privilege."""
    rows = await db.scalars(
        select(User).where(User.admin_role != "none").order_by(User.email)
    )
    return [
        {
            "id": str(u.id), "email": u.email, "full_name": u.full_name,
            "admin_role": u.admin_role, "is_active": u.is_active,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in rows.all()
    ]


async def change_admin_role(db: AsyncSession, user: User, role: str) -> User:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    user.admin_role = role
    # Promotion to a staff role also flips the legacy is_admin flag so older
    # code paths (which still check is_admin) treat them consistently.
    user.is_admin = role not in ("none",)
    await db.flush()
    return user


async def force_logged_out_count() -> int:
    """How many users currently have an active denylist entry."""
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            keys = await r.keys("auth:denylist:*")
            return len(keys)
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        return 0


async def recent_logins(db: AsyncSession, hours: int = 72,
                        limit: int = 100) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = await db.scalars(
        select(User).where(User.last_login_at.is_not(None),
                           User.last_login_at >= since)
        .order_by(User.last_login_at.desc()).limit(limit)
    )
    return [
        {
            "id": str(u.id), "email": u.email,
            "admin_role": u.admin_role,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in rows.all()
    ]


async def force_logged_out_users(db: AsyncSession, limit: int = 50) -> list[dict]:
    """Resolve every active denylist key back to a user record."""
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1,
                              decode_responses=True)
        try:
            keys = await r.keys("auth:denylist:*")
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        return []

    out: list[dict] = []
    for key in keys[:limit]:
        try:
            uid = uuid.UUID(key.split(":")[-1])
        except ValueError:
            continue
        u = await db.get(User, uid)
        if u is None:
            continue
        out.append({
            "id": str(u.id), "email": u.email,
            "admin_role": u.admin_role, "is_active": u.is_active,
        })
    return out
