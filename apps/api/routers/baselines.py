from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.schemas.baselines import (
    BaselineDetail,
    BaselineListResponse,
    BaselineSummary,
    WadeDiagnostic,
    WadeGroupedFinding,
    WadeHistoryItem,
    WadeHistoryResponse,
    WadeSummary,
)
from apps.api.security import get_current_user
from apps.api.services import baselines as bl_service

router = APIRouter(tags=["baselines"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]

_TOP_ANOMALY_LIMIT = 5


def _wade_metadata(scanner_metadata: dict | None) -> dict:
    m = scanner_metadata or {}
    return {
        "baseline_generated": bool(m.get("wade_baseline_generated", False)),
        "compared_to_previous_baseline": bool(m.get("wade_compared_to_previous", False)),
        "baseline_version": m.get("wade_baseline_version"),
        "anomaly_count": int(m.get("wade_anomaly_count", 0)),
    }


# ---------------------------------------------------------------------------
# Baselines — website-scoped
# ---------------------------------------------------------------------------


@router.get("/websites/{website_id}/baselines", response_model=BaselineListResponse)
async def list_baselines(
    website_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> BaselineListResponse:
    if not await bl_service.website_exists(db, website_id, user_id=current_user.id):
        raise HTTPException(status_code=404, detail="Website not found")
    items, total = await bl_service.list_baselines(
        db, website_id, limit=limit, offset=offset
    )
    return BaselineListResponse(
        items=[BaselineSummary.model_validate(b) for b in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/websites/{website_id}/baselines/latest", response_model=BaselineDetail)
async def get_latest_baseline(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> BaselineDetail:
    if not await bl_service.website_exists(db, website_id, user_id=current_user.id):
        raise HTTPException(status_code=404, detail="Website not found")
    record = await bl_service.get_latest_baseline(db, website_id)
    if record is None:
        raise HTTPException(status_code=404, detail="No baseline found for this website")
    return BaselineDetail.model_validate(record)


# ---------------------------------------------------------------------------
# Baselines — by ID
# ---------------------------------------------------------------------------


@router.get("/baselines/{baseline_record_id}", response_model=BaselineDetail)
async def get_baseline(
    baseline_record_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> BaselineDetail:
    record = await bl_service.get_baseline(
        db, baseline_record_id, user_id=current_user.id
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return BaselineDetail.model_validate(record)


@router.delete("/baselines/{baseline_record_id}", status_code=204)
async def delete_baseline(
    baseline_record_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> None:
    deleted = await bl_service.delete_baseline(
        db, baseline_record_id, user_id=current_user.id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Baseline not found")
    await db.commit()


# ---------------------------------------------------------------------------
# WADE — per scan result
# ---------------------------------------------------------------------------


@router.get("/scan-results/{scan_result_id}/wade", response_model=WadeSummary)
async def get_wade_summary(
    scan_result_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> WadeSummary:
    sr, wade_findings, wade_diag = await bl_service.get_wade_data(
        db, scan_result_id, user_id=current_user.id
    )
    if sr is None:
        raise HTTPException(status_code=404, detail="Scan result not found")

    meta = _wade_metadata(sr.scanner_metadata)

    return WadeSummary(
        scan_result_id=sr.id,
        baseline_generated=meta["baseline_generated"],
        compared_to_previous_baseline=meta["compared_to_previous_baseline"],
        baseline_version=meta["baseline_version"],
        anomaly_count=meta["anomaly_count"],
        wade_findings=[WadeGroupedFinding.model_validate(f) for f in wade_findings],
        wade_diagnostic=WadeDiagnostic.model_validate(wade_diag) if wade_diag else None,
    )


# ---------------------------------------------------------------------------
# WADE — history per website
# ---------------------------------------------------------------------------


@router.get("/websites/{website_id}/wade/history", response_model=WadeHistoryResponse)
async def get_wade_history(
    website_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> WadeHistoryResponse:
    if not await bl_service.website_exists(db, website_id, user_id=current_user.id):
        raise HTTPException(status_code=404, detail="Website not found")

    results, total = await bl_service.get_wade_history(
        db, website_id, limit=limit, offset=offset
    )

    items: list[WadeHistoryItem] = []
    for sr in results:
        meta = _wade_metadata(sr.scanner_metadata)
        wade_gf = [
            gf for gf in sr.grouped_findings if gf.scanner_engine == "wade"
        ]
        top_titles = [gf.title for gf in wade_gf[:_TOP_ANOMALY_LIMIT]]
        items.append(
            WadeHistoryItem(
                scan_result_id=sr.id,
                scan_job_id=sr.scan_job_id,
                created_at=sr.created_at,
                anomaly_count=meta["anomaly_count"],
                risk_score=sr.risk_score,
                risk_level=sr.risk_level,
                top_anomaly_titles=top_titles,
            )
        )

    return WadeHistoryResponse(
        items=items, total=total, limit=limit, offset=offset
    )
