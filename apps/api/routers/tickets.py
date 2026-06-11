# WebHound — apps/api/routers/tickets.py
# Customer-facing support ticket creation. A thin AUTHENTICATED endpoint on top of
# the existing staff support system (services/support.create_ticket) so a "Create
# ticket for assistance" action (e.g. a scan blocked by a provider challenge) lands
# directly in the /control/tickets queue. No new schema/infra.
#
# Customer "kinds" (scan_blocked / onboarding_help) are mapped to the existing valid
# `question` category, with the kind + context carried in the subject/body. NEVER put
# tokens/secrets in the ticket body — only ids and the detected blocker name.

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_current_user
from apps.api.services import email as email_service
from apps.api.services import support

router = APIRouter(tags=["tickets"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]

_ALLOWED_KINDS = ("scan_blocked", "onboarding_help")


class CustomerTicketRequest(BaseModel):
    subject: str = Field(default="", max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    kind: str = "onboarding_help"          # scan_blocked | onboarding_help
    website_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    blocker: str | None = Field(default=None, max_length=64)   # e.g. "vercel" / "cloudflare"
    diagnosis: str | None = Field(default=None, max_length=32)  # cloudflare|vercel|both|unknown
    evidence: list[str] = Field(default_factory=list)          # detection signals (non-secret)


@router.post("/tickets")
async def create_customer_ticket(
    payload: CustomerTicketRequest, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Create a support ticket from the customer dashboard. Lands in the staff
    queue. Reuses the existing SupportTicket system; carries only safe context."""
    kind = payload.kind if payload.kind in _ALLOWED_KINDS else "onboarding_help"
    subject = (payload.subject or "").strip() or (
        "Scan blocked — assistance requested" if kind == "scan_blocked"
        else "Onboarding help requested")
    subject = f"[{kind}] {subject}"[:200]

    # Safe, non-secret context only — ids, the provider diagnosis, detection evidence,
    # and a logs reference staff can use. NEVER tokens/secrets.
    lines: list[str] = []
    if payload.description:
        lines.append(payload.description.strip())
    lines.append(f"request kind: {kind}")
    if payload.website_id:
        lines.append(f"website_id: {payload.website_id}")
    if payload.scan_id:
        lines.append(f"scan_id: {payload.scan_id}")
    if payload.blocker:
        lines.append(f"detected blocker: {payload.blocker}")
    if payload.diagnosis:
        lines.append(f"provider diagnosis: {payload.diagnosis}")
    if payload.evidence:
        lines.append("blocker evidence:")
        lines.extend(f"  - {str(e)[:200]}" for e in payload.evidence[:10])
    if payload.scan_id:
        lines.append(
            f"logs reference: scan {payload.scan_id}"
            + (f" on website {payload.website_id}" if payload.website_id else "")
            + " — pull via Railway logs / scan_results")
    body = "\n".join(lines)

    ticket = await support.create_ticket(
        db, user=current_user, subject=subject, description=body,
        category="question", priority="medium",
        source_scan_id=payload.scan_id, author_email=current_user.email)
    await db.commit()

    # Notify staff via the existing email path (best-effort; respects
    # notifications_enabled). Never fail ticket creation on a notification error.
    try:
        await email_service.send_staff_ticket_notification(
            ticket_number=ticket.number, subject=subject, body_text=body)
    except Exception:  # noqa: BLE001
        pass

    return {"id": str(ticket.id), "number": ticket.number, "status": ticket.status}
