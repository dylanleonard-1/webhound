# WebHound — apps/api/internal/audit.py
# Helper to append to the immutable admin audit trail. Callers add the row and
# commit within their own transaction. As of Phase 11 we also fan a typed
# telemetry event onto the live SOC stream so /control/events shows every
# privileged action in real time.

from __future__ import annotations

import logging

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.user import User
from apps.api.telemetry import Event, EventKind, Severity, publish_event
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# A few actions deserve a richer EventKind on the SOC stream than the generic
# admin.action. Mapping keeps it small + explicit — anything not listed here
# still gets a generic admin.action event (info severity).
_ACTION_KIND: dict[str, EventKind] = {
    "customer.suspend":      EventKind.CUSTOMER_SUSPENDED,
    "customer.reactivate":   EventKind.CUSTOMER_REACTIVATED,
    "customer.plan_change":  EventKind.CUSTOMER_PLAN_CHANGED,
    "ticket.create":         EventKind.TICKET_OPENED,
    "deploy.record":         EventKind.DEPLOY_RECORDED,
    "abuse.ban":             EventKind.ABUSE_USER_BANNED,
    "engine.maintenance":    EventKind.ENGINE_MAINTENANCE,
    "incident.status":       EventKind.INCIDENT_STATUS,
}

# Severities that bump above "info" — high-impact mutations the SOC should see.
_ACTION_SEVERITY: dict[str, Severity] = {
    "customer.suspend":      Severity.HIGH,
    "abuse.ban":             Severity.HIGH,
    "customer.force_logout": Severity.MEDIUM,
    "customer.plan_change":  Severity.MEDIUM,
    "engine.maintenance":    Severity.MEDIUM,
    "deploy.record":         Severity.MEDIUM,
}


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
    """Append an audit row (caller is responsible for the commit) and fire a
    matching telemetry event onto the live SOC stream. Publish is best-effort
    — Redis being unreachable must never break the audit write."""
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
    try:
        await publish_event(Event(
            kind=_ACTION_KIND.get(action, EventKind.ADMIN_ACTION),
            severity=_ACTION_SEVERITY.get(action, Severity.INFO),
            source="admin",
            message=f"{actor.email if actor else 'system'} · {action}",
            target_type=target_type, target_id=target_id,
            detail=detail or {},
            actor_email=actor.email if actor else None,
        ))
    except Exception:  # noqa: BLE001 — audit write must never fail because of telemetry
        logger.debug("audit publish_event failed", exc_info=True)
    return row
