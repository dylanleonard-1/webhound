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

    # Safe, non-secret context only.
    lines: list[str] = []
    if payload.description:
        lines.append(payload.description.strip())
    if payload.website_id:
        lines.append(f"website_id: {payload.website_id}")
    if payload.scan_id:
        lines.append(f"scan_id: {payload.scan_id}")
    if payload.blocker:
        lines.append(f"detected blocker: {payload.blocker}")
    lines.append(f"request kind: {kind}")
    body = "\n".join(lines)

    ticket = await support.create_ticket(
        db, user=current_user, subject=subject, description=body,
        category="question", priority="medium",
        source_scan_id=payload.scan_id, author_email=current_user.email)
    await db.commit()
    return {"id": str(ticket.id), "number": ticket.number, "status": ticket.status}
