# WebHound API — apps/api/routers/portfolio.py
# Phase-16 Agency/MSP portfolio routes. Purely additive + org-scoped:
# single-site users never hit these unless they open the portfolio view,
# and a 1-site org gets a valid 1-site portfolio.

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.schemas.portfolio import (
    AssignGroupRequest,
    ClientGroupCreate,
    ClientGroupListResponse,
    ClientGroupResponse,
    PortfolioAlertsResponse,
    PortfolioReportResponse,
    PortfolioSummaryResponse,
)
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import portfolio as svc

router = APIRouter(prefix="/portfolio", tags=["portfolio"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _require_org(active_org: uuid.UUID | None) -> uuid.UUID:
    if active_org is None:
        raise HTTPException(
            status_code=400,
            detail="An active organization is required for portfolio views.")
    return active_org


@router.get("/summary", response_model=PortfolioSummaryResponse)
async def portfolio_summary(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    return await svc.get_portfolio_summary(db, org_id)


@router.get("/sites")
async def portfolio_sites(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    rows = await svc.get_portfolio_rows(db, org_id)
    return {"sites": [
        {"site_id": r.site_id, "domain": r.domain, "url": r.url,
         "group_id": r.group_id, "risk_score": r.risk_score,
         "risk_level": r.risk_level, "health_score": r.health_score,
         "monitoring": r.monitoring, "last_scan_at": r.last_scan_at,
         "wade_changed": r.to_summary().wade_changed,
         "top_issue": r.top_issue}
        for r in rows], "count": len(rows)}


@router.get("/wade")
async def portfolio_wade(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    return await svc.get_portfolio_wade(db, org_id)


@router.get("/risk-rollup")
async def portfolio_risk_rollup(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    view = await svc.get_portfolio_summary(db, org_id)
    return {"rollup": view["dashboard"], "scores": view["summary"]}


@router.get("/alerts", response_model=PortfolioAlertsResponse)
async def portfolio_alerts(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    alerts = await svc.get_portfolio_alerts(db, org_id)
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/report", response_model=PortfolioReportResponse)
async def portfolio_report(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    return {"report": await svc.get_portfolio_report(db, org_id)}


@router.get("/client-groups", response_model=ClientGroupListResponse)
async def list_client_groups(
    db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    return {"groups": await svc.list_client_groups(db, org_id)}


@router.post("/client-groups", response_model=ClientGroupResponse,
             status_code=201)
async def create_client_group(
    data: ClientGroupCreate, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    group = await svc.create_client_group(
        db, org_id, name=data.name, group_type=data.group_type,
        parent_group_id=data.parent_group_id)
    await db.commit()
    return group


@router.patch("/sites/{site_id}/group", status_code=204)
async def assign_site_group(
    site_id: uuid.UUID, data: AssignGroupRequest, db: _DB,
    current_user: _CurrentUser, active_org: _ActiveOrg = None,
):
    org_id = _require_org(active_org)
    ok = await svc.assign_site_to_group(db, org_id, site_id, data.group_id)
    if not ok:
        raise HTTPException(status_code=404,
                            detail="Site or group not found in this org.")
    await db.commit()
