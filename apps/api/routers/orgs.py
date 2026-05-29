# WebHound — apps/api/routers/orgs.py
# Phase-4 slice B: org management endpoints + active-org discovery.
#
# /orgs               GET  — list the caller's orgs (memberships only)
# /orgs               POST — create a new org (caller becomes OWNER)
# /orgs/active        GET  — echo the resolved active org context
#                            (for client-side org-switcher UIs)

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.enums import OrgRole, PlanTier
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services.orgs import (
    OrgServiceError,
    create_org,
    list_user_orgs,
)

router = APIRouter(prefix="/orgs", tags=["orgs"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


class OrgMembershipView(BaseModel):
    """One row of the caller's org list — the org plus the caller's
    role in it."""

    id: uuid.UUID
    slug: str
    name: str
    plan_tier: PlanTier
    role: OrgRole
    is_active: bool

    model_config = {"from_attributes": True}


class OrgListResponse(BaseModel):
    items: list[OrgMembershipView]
    total: int


class OrgCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=63)
    billing_email: str | None = None


class ActiveOrgResponse(BaseModel):
    """Echo of the resolved active-org context. ``active_org_id=None``
    means the caller didn't supply ``X-Org-Id`` and is operating in
    single-tenant legacy mode."""

    active_org_id: uuid.UUID | None


@router.get("", response_model=OrgListResponse)
async def list_orgs(
    db: _DB, current_user: _CurrentUser,
) -> OrgListResponse:
    rows = await list_user_orgs(db, current_user.id)
    items = [
        OrgMembershipView(
            id=o.id, slug=o.slug, name=o.name,
            plan_tier=o.plan_tier, role=role, is_active=o.is_active,
        )
        for o, role in rows
    ]
    return OrgListResponse(items=items, total=len(items))


@router.post("", response_model=OrgMembershipView, status_code=201)
async def create_new_org(
    payload: OrgCreateRequest, db: _DB, current_user: _CurrentUser,
) -> OrgMembershipView:
    try:
        org = await create_org(
            db,
            name=payload.name,
            slug=payload.slug,
            owner_user_id=current_user.id,
            billing_email=payload.billing_email,
        )
    except OrgServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    # Founder is always OWNER per create_org's contract.
    return OrgMembershipView(
        id=org.id, slug=org.slug, name=org.name,
        plan_tier=org.plan_tier, role=OrgRole.OWNER,
        is_active=org.is_active,
    )


@router.get("/active", response_model=ActiveOrgResponse)
async def get_active_org(
    active_org_id: _ActiveOrg,
) -> ActiveOrgResponse:
    """Returns the resolved active org context. Useful for the
    front-end's org-switcher to confirm which org the X-Org-Id header
    currently selects (or that none is selected). A 403 from
    ``get_active_org_id`` propagates automatically when the header
    points at an org the caller isn't a member of."""
    return ActiveOrgResponse(active_org_id=active_org_id)
