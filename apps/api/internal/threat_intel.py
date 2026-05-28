# WebHound — apps/api/internal/threat_intel.py
# Phase 9A: Threat-intelligence indicator management. Reads are READ_ONLY+,
# manual add/import are ANALYST+, delete + bulk import are ADMIN.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.services import threat_intel as ti_svc

router = APIRouter(prefix="/internal/threat-intel", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _IndicatorBody(BaseModel):
    kind: str
    value: str
    source: str = "manual"
    severity: str = "medium"
    confidence: int = 80
    tags: list[str] | None = None
    notes: str | None = None
    expires_at: datetime | None = None


class _ImportBody(BaseModel):
    source: str
    rows: list[dict]
    default_severity: str = "medium"
    default_confidence: int = 70
    expires_in_days: int | None = 30


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.get("/indicators")
async def list_indicators(
    admin: _Read, db: _DB,
    kind: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    include_expired: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    rows, total = await ti_svc.search(
        db, kind=kind, source=source, severity=severity, q=q,
        include_expired=include_expired, limit=limit, offset=offset,
    )
    return {"items": [ti_svc.to_dict(r) for r in rows],
            "total": total, "limit": limit, "offset": offset}


@router.get("/indicators/match")
async def match_indicator(kind: str, value: str, admin: _Read, db: _DB) -> dict:
    hits = await ti_svc.match(db, kind=kind, value=value)
    return {"hits": [ti_svc.to_dict(h) for h in hits], "count": len(hits)}


@router.post("/indicators")
async def add_indicator(body: _IndicatorBody, admin: _Op, db: _DB,
                        request: Request) -> dict:
    try:
        row, created = await ti_svc.upsert_indicator(
            db, kind=body.kind, value=body.value, source=body.source,
            severity=body.severity, confidence=body.confidence,
            tags=body.tags, notes=body.notes, expires_at=body.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin,
                        action="threat_intel.add" if created else "threat_intel.update",
                        target_type="threat_indicator", target_id=str(row.id),
                        detail={"kind": body.kind, "value": body.value,
                                "source": body.source},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "id": str(row.id), "created": created}


@router.delete("/indicators/{indicator_id}")
async def delete_indicator(indicator_id: uuid.UUID, admin: _Admin, db: _DB,
                           request: Request) -> dict:
    deleted = await ti_svc.delete_indicator(db, indicator_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Indicator not found")
    await record_action(db, actor=admin, action="threat_intel.delete",
                        target_type="threat_indicator", target_id=str(indicator_id),
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True}


@router.post("/import")
async def import_feed(body: _ImportBody, admin: _Admin, db: _DB,
                      request: Request) -> dict:
    counts = await ti_svc.import_feed(
        db, source=body.source, rows=body.rows,
        default_severity=body.default_severity,
        default_confidence=body.default_confidence,
        expires_in_days=body.expires_in_days,
    )
    await record_action(db, actor=admin, action="threat_intel.import",
                        target_type="threat_intel_feed", target_id=body.source,
                        detail=counts, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, **counts}


@router.post("/refresh")
async def refresh_public_feeds(admin: _Admin, db: _DB, request: Request) -> dict:
    """On-demand trigger for the auto-importer beat task. Runs the same logic
    as the Sunday cron — useful right after enabling WEBHOUND_THREAT_FEEDS_ENABLED
    or to refresh on demand. Returns per-feed import counts."""
    from worker.threat_intel_tasks import _run as _import_run, _enabled
    if not _enabled():
        raise HTTPException(
            status_code=409,
            detail="Threat-intel auto-import is disabled. Set WEBHOUND_THREAT_FEEDS_ENABLED=1 on the worker service.",
        )
    result = await _import_run()
    await record_action(db, actor=admin, action="threat_intel.refresh",
                        target_type="threat_intel_feed",
                        detail={"feeds": [f.get("source") for f in result.get("feeds", [])]},
                        **_audit_ctx(request))
    await db.commit()
    return result
