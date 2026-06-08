# WebHound — apps/api/internal/admin_bypass.py
#
# Single gatekeeper for the two admin security-bypass flags:
#
#   ADMIN_VERIFY_BYPASS  — admin marks a domain "verified" without the DNS
#                          ownership check (SSRF / abuse risk).
#   ADMIN_QUOTA_BYPASS   — admin runs scans past plan quota.
#
# Rules enforced here (see docs/env.md):
#   * Default off — the flag must be explicitly enabled.
#   * Only honoured for users with is_admin = True. Never for normal users.
#   * In production the bypass is REFUSED unless ADMIN_BYPASS_ALLOW_IN_PROD=1
#     is also set (config.py refuses to even boot otherwise, so reaching here
#     in prod already implies the override — we re-check defensively).
#   * Every *use* writes an immutable admin-audit row.
#
# When neither flag is set, the verification and quota controls run normally.

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.internal.audit import record_action
from apps.api.models.user import User

logger = logging.getLogger(__name__)


def _flag_active(user: User, flag_enabled: bool) -> bool:
    """Pure gate: is the given bypass flag honoured for this user, now?"""
    if not flag_enabled:
        return False
    if not getattr(user, "is_admin", False):
        return False
    settings = get_settings()
    if settings.app_env == "production" and not settings.admin_bypass_allow_in_prod:
        logger.warning(
            "admin bypass requested in production without "
            "ADMIN_BYPASS_ALLOW_IN_PROD — refused (user=%s)",
            getattr(user, "email", "?"),
        )
        return False
    return True


def quota_bypass_allowed(user: User) -> bool:
    return _flag_active(user, get_settings().admin_quota_bypass)


def verify_bypass_allowed(user: User) -> bool:
    return _flag_active(user, get_settings().admin_verify_bypass)


async def _record(db: AsyncSession, user: User, kind: str, *, target_type: str | None,
                  target_id: str | None, detail: dict | None) -> None:
    """Append an audit row for a bypass use and commit it independently.

    Committing immediately (rather than relying on the caller's later commit)
    guarantees the bypass is recorded even if the downstream operation fails.
    record_action only db.add()s + best-effort publishes telemetry.
    """
    await record_action(
        db,
        actor=user,
        action=f"admin.bypass.{kind}",
        target_type=target_type,
        target_id=target_id,
        detail={"flag": kind, **(detail or {})},
    )
    await db.commit()


async def consume_quota_bypass(db: AsyncSession, user: User) -> bool:
    """Return True (and audit) if this admin may skip quota enforcement."""
    if not quota_bypass_allowed(user):
        return False
    await _record(db, user, "quota", target_type="user", target_id=str(user.id),
                  detail=None)
    logger.warning("ADMIN_QUOTA_BYPASS used by %s", user.email)
    return True


async def consume_verify_bypass(db: AsyncSession, user: User, website) -> bool:
    """Return True (and audit) if this admin may skip domain verification."""
    if not verify_bypass_allowed(user):
        return False
    await _record(db, user, "verify", target_type="website",
                  target_id=str(getattr(website, "id", "")),
                  detail={"hostname": getattr(website, "hostname", None)})
    logger.warning(
        "ADMIN_VERIFY_BYPASS used by %s for %s",
        user.email, getattr(website, "hostname", "?"),
    )
    return True
