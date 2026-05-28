# WebHound — apps/api/internal/logs.py
# Phase 8: Log Explorer + Audit browser API. Both surfaces support filters,
# free-text search, and CSV export.

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.services import logs as log_svc

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_DB = Annotated[AsyncSession, Depends(get_db)]


# --- Log Explorer ----------------------------------------------------------


@router.get("/logs")
async def search_logs(
    admin: _Read, db: _DB,
    source: str | None = None,
    severity: str | None = None,
    severity_at_least: str | None = None,
    q: Annotated[str | None, Query(description="substring match on message")] = None,
    request_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    rows, total = await log_svc.search_logs(
        db, source=source, severity=severity, severity_at_least=severity_at_least,
        q=q, request_id=request_id, since=since, until=until,
        limit=limit, offset=offset,
    )
    return {
        "items": [log_svc.log_to_dict(r) for r in rows],
        "total": total, "limit": limit, "offset": offset,
    }


@router.get("/logs.csv")
async def export_logs(
    admin: _Read, db: _DB,
    source: str | None = None,
    severity_at_least: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    request_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
) -> Response:
    rows, _ = await log_svc.search_logs(
        db, source=source, severity=severity, severity_at_least=severity_at_least,
        q=q, request_id=request_id, since=since, until=until,
        limit=limit, offset=0,
    )
    body = log_svc.logs_to_csv(rows)
    return Response(content=body, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="logs.csv"'})


# --- Audit browser ---------------------------------------------------------


@router.get("/audit")
async def search_audit(
    admin: _Read, db: _DB,
    action: str | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    rows, total = await log_svc.search_audit(
        db, action=action, actor_email=actor_email,
        target_type=target_type, target_id=target_id, q=q,
        since=since, until=until, limit=limit, offset=offset,
    )
    return {
        "items": [log_svc.audit_to_dict(r) for r in rows],
        "total": total, "limit": limit, "offset": offset,
    }


@router.get("/audit.csv")
async def export_audit(
    admin: _Read, db: _DB,
    action: str | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
) -> Response:
    rows, _ = await log_svc.search_audit(
        db, action=action, actor_email=actor_email,
        target_type=target_type, target_id=target_id, q=q,
        since=since, until=until, limit=limit, offset=0,
    )
    body = log_svc.audit_to_csv(rows)
    return Response(content=body, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit.csv"'})
