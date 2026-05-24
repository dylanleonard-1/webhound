from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.quota import check_export_allowed, violation_to_dict
from apps.api.database import get_db
from apps.api.pagination import page_meta
from apps.api.models.enums import ReportFormat
from apps.api.models.user import User
from apps.api.schemas.scan_results import (
    EngineDiagnosticResponse,
    FindingListResponse,
    FindingResponse,
    GroupedFindingDetailResponse,
    GroupedFindingListResponse,
    GroupedFindingResponse,
    ReportResponse,
    ScanJobSummary,
    ScanResultDetail,
    ScanResultListResponse,
    ScanResultSummary,
    WebsiteSummary,
)
from apps.api.security import get_current_user
from apps.api.services import scan_results as sr_service

router = APIRouter(prefix="/scan-results", tags=["scan-results"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]

_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


def _to_summary(record) -> ScanResultSummary:
    job = record.scan_job
    website = job.website
    return ScanResultSummary(
        id=record.id,
        scan_job_id=record.scan_job_id,
        website_id=job.website_id,
        requested_url=job.requested_url,
        hostname=website.hostname,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        duration_seconds=record.duration_seconds,
        pages_crawled=record.pages_crawled,
        total_findings=record.total_findings,
        actionable_findings=record.actionable_findings,
        severity_breakdown=record.severity_breakdown,
        created_at=record.created_at,
    )


@router.get("", response_model=ScanResultListResponse)
async def list_scan_results(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    website_id: uuid.UUID | None = None,
    scan_job_id: uuid.UUID | None = None,
    risk_level: str | None = None,
    min_risk_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    max_risk_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> ScanResultListResponse:
    if risk_level is not None and risk_level not in _VALID_RISK_LEVELS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid risk_level. Must be one of: {sorted(_VALID_RISK_LEVELS)}",
        )
    items, total = await sr_service.list_scan_results(
        db,
        limit=limit,
        offset=offset,
        website_id=website_id,
        scan_job_id=scan_job_id,
        risk_level=risk_level,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        created_from=created_from,
        created_to=created_to,
        user_id=_uid(current_user),
    )
    return ScanResultListResponse(
        items=[_to_summary(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{scan_result_id}", response_model=ScanResultDetail)
async def get_scan_result(
    scan_result_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanResultDetail:
    record = await sr_service.get_scan_result_detail(
        db, scan_result_id, user_id=_uid(current_user)
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    job = record.scan_job
    website = job.website
    return ScanResultDetail(
        id=record.id,
        scan_job_id=record.scan_job_id,
        scan_id=record.scan_id,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        duration_seconds=record.duration_seconds,
        pages_crawled=record.pages_crawled,
        total_findings=record.total_findings,
        actionable_findings=record.actionable_findings,
        severity_breakdown=record.severity_breakdown,
        scanner_metadata=record.scanner_metadata,
        created_at=record.created_at,
        scan_job=ScanJobSummary.model_validate(job),
        website=WebsiteSummary.model_validate(website),
    )


@router.get("/{scan_result_id}/grouped-findings", response_model=GroupedFindingListResponse)
async def list_grouped_findings(
    scan_result_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: str | None = None,
    category: str | None = None,
    scanner_engine: str | None = None,
    min_confidence: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> GroupedFindingListResponse:
    if await sr_service.get_scan_result(db, scan_result_id, user_id=_uid(current_user)) is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    items, total = await sr_service.list_grouped_findings(
        db,
        scan_result_id,
        limit=limit,
        offset=offset,
        severity=severity,
        category=category,
        scanner_engine=scanner_engine,
        min_confidence=min_confidence,
    )
    return GroupedFindingListResponse(
        items=[GroupedFindingResponse.model_validate(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{scan_result_id}/grouped-findings/{grouped_finding_id}", response_model=GroupedFindingDetailResponse)
async def get_grouped_finding_detail(
    scan_result_id: uuid.UUID,
    grouped_finding_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
) -> GroupedFindingDetailResponse:
    result = await sr_service.get_grouped_finding_detail(
        db, scan_result_id, grouped_finding_id, user_id=_uid(current_user)
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Grouped finding not found")
    gf, sample_findings = result
    evidence: list[dict] = [
        ev for f in sample_findings for ev in (f.evidence or [])
    ][:10]
    base = GroupedFindingResponse.model_validate(gf)
    return GroupedFindingDetailResponse(**base.model_dump(), sample_evidence=evidence)


@router.get("/{scan_result_id}/findings", response_model=FindingListResponse)
async def list_findings(
    scan_result_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: str | None = None,
    category: str | None = None,
    scanner_engine: str | None = None,
    affected_url: str | None = None,
    min_confidence: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> FindingListResponse:
    if await sr_service.get_scan_result(db, scan_result_id, user_id=_uid(current_user)) is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    items, total = await sr_service.list_findings(
        db,
        scan_result_id,
        limit=limit,
        offset=offset,
        severity=severity,
        category=category,
        scanner_engine=scanner_engine,
        affected_url=affected_url,
        min_confidence=min_confidence,
    )
    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{scan_result_id}/engine-diagnostics", response_model=list[EngineDiagnosticResponse])
async def list_engine_diagnostics(
    scan_result_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
    status: str | None = None,
    category: str | None = None,
    engine_name: str | None = None,
) -> list[EngineDiagnosticResponse]:
    if await sr_service.get_scan_result(db, scan_result_id, user_id=_uid(current_user)) is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    items = await sr_service.list_engine_diagnostics(
        db, scan_result_id, status=status, category=category, engine_name=engine_name
    )
    return [EngineDiagnosticResponse.model_validate(d) for d in items]


@router.get("/{scan_result_id}/reports", response_model=list[ReportResponse])
async def list_reports(
    scan_result_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> list[ReportResponse]:
    if await sr_service.get_scan_result(db, scan_result_id, user_id=_uid(current_user)) is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    items = await sr_service.list_reports(db, scan_result_id)
    return [ReportResponse.model_validate(r) for r in items]


@router.get("/{scan_result_id}/reports/{fmt}", response_model=ReportResponse)
async def get_report_by_format(
    scan_result_id: uuid.UUID, fmt: ReportFormat, db: _DB, current_user: _CurrentUser
) -> ReportResponse:
    if not current_user.is_admin:
        v = check_export_allowed(current_user)
        if v is not None:
            raise HTTPException(status_code=402, detail=violation_to_dict(v))
    if await sr_service.get_scan_result(db, scan_result_id, user_id=_uid(current_user)) is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    report = await sr_service.get_report_by_format(db, scan_result_id, fmt.value)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"No {fmt.value} report available for this scan result",
        )
    return ReportResponse.model_validate(report)
