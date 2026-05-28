# WebHound — apps/api/internal/team_deploys.py
# Phase 7: Team management + deploys + infra trends + maintenance toggle.
# Role changes and maintenance toggle are SUPER_ADMIN-only; everything else
# is at least READ_ONLY+.

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
from apps.api.services import deployments as deploy_svc
from apps.api.services import infra_metrics as infra_svc
from apps.api.services import maintenance as maint_svc
from apps.api.services import team as team_svc

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_Super = Annotated[User, Depends(require_admin(AdminRole.SUPER_ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _RoleBody(BaseModel):
    role: str


class _DeployBody(BaseModel):
    service: str
    sha: str
    status: str = "succeeded"
    note: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class _MaintenanceBody(BaseModel):
    active: bool
    reason: str | None = None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


# --- Team -------------------------------------------------------------------


@router.get("/team")
async def list_team(admin: _Read, db: _DB) -> dict:
    return {
        "staff": await team_svc.list_staff(db),
        "force_logged_out_count": await team_svc.force_logged_out_count(),
    }


@router.get("/team/sessions")
async def team_sessions(
    admin: _Read, db: _DB,
    hours: Annotated[int, Query(ge=1, le=720)] = 72,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    return {
        "recent_logins": await team_svc.recent_logins(db, hours=hours, limit=limit),
        "force_logged_out": await team_svc.force_logged_out_users(db, limit=limit),
    }


@router.post("/team/{user_id}/role")
async def change_role(user_id: uuid.UUID, body: _RoleBody, admin: _Super,
                      db: _DB, request: Request) -> dict:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    prior = user.admin_role
    try:
        await team_svc.change_admin_role(db, user, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="team.role_change",
                        target_type="user", target_id=str(user_id),
                        detail={"from": prior, "to": body.role}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "admin_role": body.role}


# --- Deploys ----------------------------------------------------------------


@router.get("/deploys")
async def list_deploys(admin: _Read, db: _DB,
                       service: str | None = None,
                       limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict:
    return {
        "current_sha": deploy_svc.current_sha(),
        "items": await deploy_svc.list_recent(db, service=service, limit=limit),
    }


@router.get("/deploys/current")
async def current_deploy(admin: _Read) -> dict:
    return {"sha": deploy_svc.current_sha()}


@router.post("/deploys")
async def record_deploy(body: _DeployBody, admin: _Admin, db: _DB,
                        request: Request) -> dict:
    try:
        dep = await deploy_svc.record(
            db, service=body.service, sha=body.sha, status=body.status,
            note=body.note, started_at=body.started_at, finished_at=body.finished_at,
            actor_email=admin.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="deploy.record",
                        target_type="deployment", target_id=str(dep.id),
                        detail={"service": body.service, "sha": body.sha,
                                "status": body.status}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "id": str(dep.id)}


# --- Infra trends -----------------------------------------------------------


@router.get("/infra/history")
async def infra_history(
    admin: _Read, db: _DB,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict:
    return {"items": await infra_svc.history(db, hours=hours)}


# --- Maintenance mode -------------------------------------------------------


@router.get("/maintenance")
async def maintenance_status(admin: _Read) -> dict:
    return await maint_svc.status()


@router.post("/maintenance")
async def set_maintenance(body: _MaintenanceBody, admin: _Super,
                          request: Request, db: _DB) -> dict:
    if body.active:
        await maint_svc.engage(body.reason)
    else:
        await maint_svc.disengage()
    await record_action(db, actor=admin,
                        action="maintenance.engage" if body.active else "maintenance.disengage",
                        detail={"reason": body.reason} if body.active else {},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "active": body.active}
