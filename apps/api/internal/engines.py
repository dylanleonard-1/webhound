# WebHound — apps/api/internal/engines.py
# Phase 10: engine registry mutations (maintenance toggle, auto-disable
# threshold). ANALYST+ can toggle maintenance; ADMIN sets the auto-disable
# threshold (it's a sharper instrument).

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.services import engines as engines_svc
from apps.api.telemetry import Event, EventKind, Severity, publish_event

router = APIRouter(prefix="/internal/engines", tags=["internal"])

_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _MaintBody(BaseModel):
    on: bool
    notes: str | None = None


class _ThresholdBody(BaseModel):
    failure_pct: int | None = None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.post("/{name}/maintenance")
async def toggle_maintenance(name: str, body: _MaintBody, admin: _Op, db: _DB,
                             request: Request) -> dict:
    row = await engines_svc.set_maintenance(db, name, on=body.on,
                                            actor_email=admin.email)
    if body.notes is not None:
        row.notes = body.notes
    await record_action(db, actor=admin,
                        action="engine.maintenance",
                        target_type="engine", target_id=name,
                        detail={"on": body.on, "notes": body.notes},
                        **_audit_ctx(request))
    await db.commit()
    await publish_event(Event(
        kind=EventKind.ENGINE_MAINTENANCE,
        severity=Severity.MEDIUM if body.on else Severity.INFO,
        source="engine_registry",
        message=f"Engine '{name}' maintenance {'engaged' if body.on else 'cleared'}",
        target_type="engine", target_id=name, actor_email=admin.email,
    ))
    return {"ok": True, "maintenance_mode": body.on}


@router.post("/{name}/threshold")
async def set_threshold(name: str, body: _ThresholdBody, admin: _Admin, db: _DB,
                        request: Request) -> dict:
    await engines_svc.set_auto_disable_threshold(
        db, name, failure_pct=body.failure_pct, actor_email=admin.email,
    )
    await record_action(db, actor=admin,
                        action="engine.threshold",
                        target_type="engine", target_id=name,
                        detail={"failure_pct": body.failure_pct},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "auto_disable_at_failure_pct": body.failure_pct}
