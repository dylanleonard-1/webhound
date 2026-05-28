# WebHound — apps/api/internal/support.py
# Phase 6: Support / Fix Service — ticket triage, lifecycle, timeline,
# verification rescan. RBAC-gated + audited.

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole, ScanProfile
from apps.api.models.scan_job import ScanJob
from apps.api.models.support_ticket import SupportTicket
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.schemas.scan_jobs import ScanJobCreate
from apps.api.services import scan_jobs as sj_service
from apps.api.services import support as support_svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Support = Annotated[User, Depends(require_admin(AdminRole.SUPPORT))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _CreateBody(BaseModel):
    user_id: uuid.UUID | None = None
    subject: str
    description: str | None = None
    category: str = "remediation"
    priority: str = "medium"
    source_scan_id: uuid.UUID | None = None


class _StatusBody(BaseModel):
    status: str


class _PriorityBody(BaseModel):
    priority: str


class _AssignBody(BaseModel):
    assignee_id: uuid.UUID | None = None


class _CommentBody(BaseModel):
    body: str
    visibility: str = "public"


class _RescanBody(BaseModel):
    profile: str = "standard"


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


def _ticket_dict(t: SupportTicket) -> dict:
    return {
        "id": str(t.id),
        "number": t.number,
        "user_id": str(t.user_id) if t.user_id else None,
        "assignee_id": str(t.assignee_id) if t.assignee_id else None,
        "subject": t.subject,
        "category": t.category,
        "priority": t.priority,
        "status": t.status,
        "source_scan_id": str(t.source_scan_id) if t.source_scan_id else None,
        "verification_scan_id": str(t.verification_scan_id) if t.verification_scan_id else None,
        "sla_due_at": t.sla_due_at.isoformat() if t.sla_due_at else None,
        "opened_at": t.opened_at.isoformat() if t.opened_at else None,
        "first_response_at": t.first_response_at.isoformat() if t.first_response_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "closed_at": t.closed_at.isoformat() if t.closed_at else None,
        "breached": support_svc.is_breached(t),
    }


@router.get("/tickets")
async def list_tickets(
    admin: _Read, db: _DB,
    status: str | None = None,
    priority: str | None = None,
    assignee_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    breached_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    items, total = await support_svc.search(
        db, status=status, priority=priority, assignee_id=assignee_id,
        user_id=user_id, breached_only=breached_only, limit=limit, offset=offset,
    )
    return {"items": [_ticket_dict(t) for t in items], "total": total,
            "limit": limit, "offset": offset}


@router.get("/tickets/summary")
async def tickets_summary(admin: _Read, db: _DB) -> dict:
    return await support_svc.summary(db)


@router.get("/tickets/{ticket_id}")
async def ticket_detail(ticket_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    t = await db.get(SupportTicket, ticket_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    out = _ticket_dict(t)
    out["description"] = t.description
    out["events"] = await support_svc.list_events(db, ticket_id, include_internal=True)
    # Enrich with subject email + assignee email.
    if t.user_id:
        u = await db.get(User, t.user_id)
        out["user_email"] = u.email if u else None
    if t.assignee_id:
        a = await db.get(User, t.assignee_id)
        out["assignee_email"] = a.email if a else None
    return out


async def _load(db: AsyncSession, ticket_id: uuid.UUID) -> SupportTicket:
    t = await db.get(SupportTicket, ticket_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return t


@router.post("/tickets")
async def create_ticket(body: _CreateBody, admin: _Support, db: _DB,
                        request: Request) -> dict:
    user = await db.get(User, body.user_id) if body.user_id else None
    if body.user_id and user is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    try:
        ticket = await support_svc.create_ticket(
            db, user=user, subject=body.subject, description=body.description,
            category=body.category, priority=body.priority,
            source_scan_id=body.source_scan_id, author_email=admin.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="ticket.create",
                        target_type="ticket", target_id=str(ticket.id),
                        detail={"number": ticket.number, "user_id": str(body.user_id) if body.user_id else None},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "id": str(ticket.id), "number": ticket.number}


@router.post("/tickets/{ticket_id}/status")
async def change_status(ticket_id: uuid.UUID, body: _StatusBody,
                        admin: _Support, db: _DB, request: Request) -> dict:
    t = await _load(db, ticket_id)
    try:
        await support_svc.change_status(db, t, body.status, actor_email=admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="ticket.status",
                        target_type="ticket", target_id=str(ticket_id),
                        detail={"status": body.status}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": body.status}


@router.post("/tickets/{ticket_id}/priority")
async def change_priority(ticket_id: uuid.UUID, body: _PriorityBody,
                          admin: _Support, db: _DB, request: Request) -> dict:
    t = await _load(db, ticket_id)
    try:
        await support_svc.change_priority(db, t, body.priority, actor_email=admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="ticket.priority",
                        target_type="ticket", target_id=str(ticket_id),
                        detail={"priority": body.priority}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "priority": body.priority}


@router.post("/tickets/{ticket_id}/assign")
async def assign_ticket(ticket_id: uuid.UUID, body: _AssignBody,
                        admin: _Support, db: _DB, request: Request) -> dict:
    t = await _load(db, ticket_id)
    assignee = await db.get(User, body.assignee_id) if body.assignee_id else None
    if body.assignee_id and assignee is None:
        raise HTTPException(status_code=404, detail="Assignee not found")
    await support_svc.assign(db, t, assignee, actor_email=admin.email)
    await record_action(db, actor=admin, action="ticket.assign",
                        target_type="ticket", target_id=str(ticket_id),
                        detail={"assignee": assignee.email if assignee else None},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "assignee": assignee.email if assignee else None}


@router.post("/tickets/{ticket_id}/comment")
async def comment_ticket(ticket_id: uuid.UUID, body: _CommentBody,
                         admin: _Support, db: _DB, request: Request) -> dict:
    text = body.body.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Comment body required")
    t = await _load(db, ticket_id)
    try:
        await support_svc.add_event(db, t, kind="comment", body=text,
                                    visibility=body.visibility,
                                    author_email=admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await record_action(db, actor=admin, action="ticket.comment",
                        target_type="ticket", target_id=str(ticket_id),
                        detail={"visibility": body.visibility}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True}


@router.post("/tickets/{ticket_id}/verify-rescan")
async def verify_rescan(ticket_id: uuid.UUID, body: _RescanBody,
                        admin: _Support, db: _DB, request: Request) -> dict:
    """Trigger a staff-initiated verification scan, link it to the ticket."""
    t = await _load(db, ticket_id)
    if t.source_scan_id is None:
        raise HTTPException(status_code=422,
                            detail="Ticket has no source_scan to verify against")
    source = await db.get(ScanJob, t.source_scan_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source scan not found")
    try:
        profile = ScanProfile(body.profile)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid profile: {body.profile}")
    new_scan = await sj_service.create_scan_job(
        db,
        ScanJobCreate(website_id=source.website_id, profile=profile),
        is_admin=True,
    )
    await support_svc.attach_verification_scan(db, t, new_scan,
                                               actor_email=admin.email)
    await db.commit()
    await db.refresh(new_scan)
    # Best-effort enqueue (mirrors scan_ops.force_rescan).
    try:
        from worker.scan_tasks import run_scan
        task = run_scan.delay(str(new_scan.id), new_scan.requested_url, new_scan.profile.value)
        new_scan.celery_task_id = task.id
        await db.commit()
    except Exception:  # noqa: BLE001
        logger.warning("failed to enqueue verification rescan for ticket %s", ticket_id)
    await record_action(db, actor=admin, action="ticket.verify_rescan",
                        target_type="ticket", target_id=str(ticket_id),
                        detail={"verification_scan": str(new_scan.id)},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "verification_scan_id": str(new_scan.id)}
