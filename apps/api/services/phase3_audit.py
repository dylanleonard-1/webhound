# WebHound — apps/api/services/phase3_audit.py
# Phase 3.8 — centralized, append-only audit trail for Phase-3 onboarding
# actions. REUSES the existing admin_audit_log table (no second audit platform):
# rows are written DIRECTLY here (NOT via record_action), so customer onboarding
# events are not fanned onto the staff SOC live stream. Customer events are
# distinguished by their namespaced action + actor_role IS NULL.
#
# Security: sensitive values are redacted via the existing redact() utility, and
# — the primary control — no phase ever puts tokens/secrets in its metadata.

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.website import Website
from apps.api.platform.observability.structured_logging import redact

# Evidence tags stored on every Phase-3 audit event — material that MAY support
# future certification efforts. No certification is claimed.
COMPLIANCE_TAGS = ["SOC2", "ISO27001", "GDPR", "HIPAA_READINESS", "ENTERPRISE"]

# Action namespaces that make up the Phase-3 onboarding audit trail.
PHASE3_ACTION_PREFIXES = (
    "website.verification.", "provider.", "trusted_access.",
    "access_validation.", "challenge.", "onboarding.",
    "monitoring.", "deep_scan.", "automation.", "cloudflare.", "vercel.",
)


def record_phase3_event(
    db: AsyncSession, *, event_type: str, website: Website,
    actor_user_id: uuid.UUID | None = None, org_id: uuid.UUID | None = None,
    provider: str | None = None, resource_type: str | None = None,
    resource_id: Any = None, status: str | None = None, reason: str | None = None,
    metadata: dict | None = None, compliance_tags: list[str] | None = None,
) -> None:
    """Append a Phase-3 audit row to admin_audit_log.

    SYNC — only db.add(); the row persists on the caller's existing commit, so
    this slots in beside the existing (sync) event emits without touching them.
    The row always targets the WEBSITE (target_id) so the per-website history
    query finds every event; any sub-resource (e.g. a trusted-access profile)
    is recorded in detail.resource_*.
    """
    detail: dict[str, Any] = {
        "org_id": str(org_id) if org_id else (str(website.org_id) if website.org_id else None),
        "domain": website.hostname,
        "provider": provider,
        "status": status,
        "reason": reason,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "compliance_tags": compliance_tags or COMPLIANCE_TAGS,
    }
    if metadata:
        detail["metadata"] = metadata
    db.add(AdminAuditLog(
        actor_user_id=actor_user_id,
        action=event_type,
        target_type="website",
        target_id=str(website.id),
        detail=redact(detail),
    ))


def _to_event(row: AdminAuditLog) -> dict:
    d = row.detail or {}
    return {
        "event_type": row.action,
        "resource_type": d.get("resource_type"),
        "resource_id": d.get("resource_id"),
        "domain": d.get("domain"),
        "provider": d.get("provider"),
        "status": d.get("status"),
        "reason": d.get("reason"),
        "compliance_tags": d.get("compliance_tags"),
        "created_at": row.created_at,
    }


async def get_onboarding_history(db: AsyncSession, website: Website) -> dict:
    """Append-only Phase-3 onboarding audit trail for a website — timeline +
    dashboard contract. Tenant isolation is enforced by the caller (the website
    is looked up scoped to the owner)."""
    rows = list(await db.scalars(
        sa.select(AdminAuditLog).where(
            AdminAuditLog.target_id == str(website.id),
            AdminAuditLog.actor_role.is_(None),  # customer events, not staff /control
            sa.or_(*[AdminAuditLog.action.like(p + "%") for p in PHASE3_ACTION_PREFIXES]),
        ).order_by(AdminAuditLog.created_at.asc())
    ))
    events = [_to_event(r) for r in rows]

    def _last(prefix: str):
        for r in reversed(rows):
            if r.action.startswith(prefix):
                return r.created_at
        return None

    return {
        "audit_trail_available": len(events) > 0,
        "event_count": len(events),
        "last_verification": _last("website.verification."),
        "last_validation": _last("access_validation."),
        "last_monitoring_change": _last("monitoring."),
        "last_provider_change": _last("provider."),
        "timeline": events,
    }
