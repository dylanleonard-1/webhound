# WebHound — apps/api/internal/incidents.py
# Phase 10: SOC incident API. Reads READ_ONLY+; lifecycle ANALYST+; assign ADMIN.

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole
from apps.api.models.incident import Incident
from apps.api.models.user import User
from apps.api.services import incidents as inc_svc

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _StatusBody(BaseModel):
    status: str


class _AssignBody(BaseModel):
    assignee_id: uuid.UUID | None = None


class _NoteBody(BaseModel):
    body: str


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.get("/incidents")
async def list_incidents(
    admin: _Read, db: _DB,
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    breached_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    items, total = await inc_svc.search(
        db, status=status, severity=severity, source=source,
        breached_only=breached_only, limit=limit, offset=offset,
    )
    return {"items": [inc_svc.to_dict(i) for i in items], "total": total,
            "limit": limit, "offset": offset}


@router.get("/incidents/summary")
async def incidents_summary(admin: _Read, db: _DB) -> dict:
    return await inc_svc.summary(db)


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    i = await db.get(Incident, incident_id)
    if i is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    out = inc_svc.to_dict(i)
    out["events"] = await inc_svc.list_events(db, incident_id)
    if i.assignee_id:
        u = await db.get(User, i.assignee_id)
        out["assignee_email"] = u.email if u else None
    return out


async def _load(db: AsyncSession, incident_id: uuid.UUID) -> Incident:
    i = await db.get(Incident, incident_id)
    if i is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return i


@router.post("/incidents/{incident_id}/status")
async def change_status(incident_id: uuid.UUID, body: _StatusBody, admin: _Op,
                        db: _DB, request: Request) -> dict:
    i = await _load(db, incident_id)
    try:
        await inc_svc.change_status(db, i, body.status, actor_email=admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="incident.status",
                        target_type="incident", target_id=str(incident_id),
                        detail={"status": body.status}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": body.status}


@router.post("/incidents/{incident_id}/assign")
async def assign_incident(incident_id: uuid.UUID, body: _AssignBody,
                          admin: _Admin, db: _DB, request: Request) -> dict:
    i = await _load(db, incident_id)
    assignee_email = None
    if body.assignee_id is not None:
        a = await db.get(User, body.assignee_id)
        if a is None:
            raise HTTPException(status_code=404, detail="Assignee not found")
        assignee_email = a.email
    await inc_svc.assign(db, i, assignee_id=body.assignee_id,
                         assignee_email=assignee_email, actor_email=admin.email)
    await record_action(db, actor=admin, action="incident.assign",
                        target_type="incident", target_id=str(incident_id),
                        detail={"assignee": assignee_email}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "assignee": assignee_email}


@router.post("/incidents/{incident_id}/note")
async def add_note(incident_id: uuid.UUID, body: _NoteBody, admin: _Op,
                   db: _DB, request: Request) -> dict:
    text = body.body.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Note body required")
    i = await _load(db, incident_id)
    await inc_svc.add_note(db, i, body=text, author_email=admin.email)
    await record_action(db, actor=admin, action="incident.note",
                        target_type="incident", target_id=str(incident_id),
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True}
