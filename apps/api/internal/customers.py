# WebHound — apps/api/internal/customers.py
# Phase 4: Customer Operations Center (search, detail, suspend/reactivate,
# force-logout, plan override, internal notes). RBAC-gated + audited.

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole, PlanTier
from apps.api.models.user import User
from apps.api.services import customers as cust_svc

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Support = Annotated[User, Depends(require_admin(AdminRole.SUPPORT))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _SuspendBody(BaseModel):
    reason: str | None = None


class _PlanBody(BaseModel):
    plan: PlanTier


class _NoteBody(BaseModel):
    body: str


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


def _row(u: User) -> dict:
    return {
        "id": str(u.id), "email": u.email, "full_name": u.full_name,
        "company_name": u.company_name,
        "plan": u.plan.value if hasattr(u.plan, "value") else str(u.plan),
        "is_active": u.is_active, "admin_role": u.admin_role,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "banned_at": u.banned_at.isoformat() if u.banned_at else None,
    }


@router.get("/customers")
async def list_customers(
    admin: _Read, db: _DB,
    q: Annotated[str | None, Query(description="search email/name/company")] = None,
    plan: str | None = None,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    items, total = await cust_svc.search(db, q=q, plan=plan, status=status,
                                         limit=limit, offset=offset)
    return {"items": [_row(u) for u in items], "total": total,
            "limit": limit, "offset": offset}


@router.get("/customers/{user_id}")
async def customer_detail(user_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    detail = await cust_svc.detail(db, user_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return detail


async def _load(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return user


@router.post("/customers/{user_id}/suspend")
async def suspend_customer(user_id: uuid.UUID, body: _SuspendBody, admin: _Admin,
                           db: _DB, request: Request) -> dict:
    user = await _load(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot suspend yourself")
    await cust_svc.suspend(db, user, reason=body.reason)
    await record_action(db, actor=admin, action="customer.suspend",
                        target_type="user", target_id=str(user_id),
                        detail={"reason": body.reason}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": "suspended"}


@router.post("/customers/{user_id}/reactivate")
async def reactivate_customer(user_id: uuid.UUID, admin: _Admin, db: _DB,
                              request: Request) -> dict:
    user = await _load(db, user_id)
    await cust_svc.reactivate(db, user)
    await record_action(db, actor=admin, action="customer.reactivate",
                        target_type="user", target_id=str(user_id), **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": "active"}


@router.post("/customers/{user_id}/force-logout")
async def force_logout_customer(user_id: uuid.UUID, admin: _Admin, db: _DB,
                                request: Request) -> dict:
    user = await _load(db, user_id)
    await cust_svc.force_logout(user)
    await record_action(db, actor=admin, action="customer.force_logout",
                        target_type="user", target_id=str(user_id), **_audit_ctx(request))
    await db.commit()
    return {"ok": True}


@router.post("/customers/{user_id}/plan")
async def change_plan(user_id: uuid.UUID, body: _PlanBody, admin: _Admin, db: _DB,
                      request: Request) -> dict:
    user = await _load(db, user_id)
    prior = user.plan.value if hasattr(user.plan, "value") else str(user.plan)
    await cust_svc.change_plan(db, user, body.plan)
    await record_action(db, actor=admin, action="customer.plan_change",
                        target_type="user", target_id=str(user_id),
                        detail={"from": prior, "to": body.plan.value},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "plan": body.plan.value}


@router.get("/customers/{user_id}/notes")
async def list_notes(user_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    return {"items": await cust_svc.list_notes(db, user_id)}


@router.post("/customers/{user_id}/notes")
async def add_note(user_id: uuid.UUID, body: _NoteBody, admin: _Support, db: _DB,
                   request: Request) -> dict:
    text = body.body.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Note body required")
    await _load(db, user_id)  # 404 if missing
    note = await cust_svc.add_note(db, user_id, body=text, author_email=admin.email)
    await record_action(db, actor=admin, action="customer.note_add",
                        target_type="user", target_id=str(user_id), **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "id": str(note.id)}


@router.delete("/notes/{note_id}")
async def delete_note(note_id: uuid.UUID, admin: _Admin, db: _DB,
                      request: Request) -> dict:
    deleted = await cust_svc.delete_note(db, note_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Note not found")
    await record_action(db, actor=admin, action="note.delete",
                        target_type="internal_note", target_id=str(note_id),
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True}
