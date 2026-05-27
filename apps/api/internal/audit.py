# WebHound — apps/api/internal/audit.py
# Helper to append to the immutable admin audit trail. Callers add the row and
# commit within their own transaction.

from __future__ import annotations

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession


async def record_action(
    db: AsyncSession,
    *,
    actor: User | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
) -> AdminAuditLog:
    """Append an audit row (caller is responsible for the commit)."""
    row = AdminAuditLog(
        actor_user_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        actor_role=getattr(actor, "admin_role", None) if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail or {},
        ip_address=ip_address,
        request_id=request_id,
    )
    db.add(row)
    return row
