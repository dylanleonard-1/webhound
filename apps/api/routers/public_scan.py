# WebHound — apps/api/routers/public_scan.py
# Slice 4.A — Public/guest scan endpoints.
#
#   POST /public/scan            — start a guest scan (URL → scan_id + token)
#   GET  /public/scan/{token}    — poll status (Slice 4.A) until SSE lands in 4.B
#
# Architecture rules (per ARCHITECTURE RULE in the brief):
#   * Reuse existing scan engine, worker, event system, rate
#     limiter, DB models.
#   * No parallel scan system. Same ScanJob row authenticated
#     scans use; the only differentiator is ``guest_token`` set.
#
# Security:
#   * IP rate limit (3/IP/day) via existing rate_limit module.
#   * Lookup always by ``guest_token``; never by scan-id from the
#     public surface, so guests cannot enumerate other guests'
#     scans.
#   * Resource limits are inherited from the scanner's own
#     target_validation (no private IPs / localhost / non-public
#     hostnames).

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.services.public_scan import (
    PublicScanError,
    check_ip_rate_limit,
    create_guest_scan,
    get_guest_scan_status,
)

router = APIRouter(prefix="/public/scan", tags=["public-scan"])

_DB = Annotated[AsyncSession, Depends(get_db)]


def _client_ip(request: Request) -> str:
    """Best-effort client-IP extraction. Honours
    ``X-Forwarded-For`` when the request originated from a known
    proxy (Railway sets this header). Falls back to the socket
    peer address."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        # XFF is a comma-separated list; the first entry is the
        # client. Strip whitespace + lowercase.
        return fwd.split(",")[0].strip().lower()
    return (request.client.host if request.client else "unknown").lower()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class PublicScanCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class PublicScanCreateResponse(BaseModel):
    scan_id: str
    guest_token: str
    status: str
    target_url: str
    started_at: str | None
    completed_at: str | None
    profile: str
    rate_limit_remaining: int


class PublicScanResultSummary(BaseModel):
    risk_score: int | None = None
    risk_level: str | None = None
    total_findings: int | None = None
    actionable_findings: int | None = None
    severity_breakdown: dict[str, Any] | None = None
    duration_seconds: float | None = None


class PublicScanStatusResponse(BaseModel):
    scan_id: str
    guest_token: str
    status: str
    target_url: str
    profile: str
    started_at: str | None
    completed_at: str | None
    error_message: str | None
    result: PublicScanResultSummary | None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=PublicScanCreateResponse, status_code=201)
async def start_public_scan(
    payload: PublicScanCreate,
    request: Request,
    db: _DB,
) -> PublicScanCreateResponse:
    """Start a guest scan. The visitor doesn't have an account;
    we issue an opaque token + return a status URL the front-end
    polls."""
    ip = _client_ip(request)
    # Pre-flight rate-limit check so we never burn a scan-job
    # creation on a throttled IP. The service-side check inside
    # ``create_guest_scan`` is the authoritative one — this is a
    # cheap shortcut that yields the same decision.
    decision = await check_ip_rate_limit(ip)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                "You’ve started 3 scans in the last 24 hours. "
                "Try again later — or create an account to keep "
                "scanning."
            ),
            headers={
                "Retry-After": str(decision.reset_seconds),
                "X-RateLimit-Remaining": "0",
            },
        )
    try:
        payload_out = await create_guest_scan(
            db, raw_url=payload.url, client_ip=ip,
        )
    except PublicScanError as exc:
        # Plain-English visitor-facing messages. PublicScanError
        # bodies are intentionally written for the dashboard
        # toast UX.
        raise HTTPException(status_code=400, detail=str(exc))
    return PublicScanCreateResponse(**payload_out)


@router.get(
    "/{guest_token}",
    response_model=PublicScanStatusResponse,
)
async def get_public_scan(
    guest_token: uuid.UUID,
    db: _DB,
) -> PublicScanStatusResponse:
    """Poll for the scan's current status. The front-end calls
    this every 2 seconds until ``status`` is ``completed`` or
    ``failed``. SSE (Slice 4.B) will replace polling without
    changing this endpoint's contract — the status page can fall
    back to polling if SSE drops.

    Returns 404 with a plain-English body when the token is
    unknown so a guess attack reveals nothing."""
    payload = await get_guest_scan_status(db, guest_token)
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="That scan link isn’t recognised. It may have expired.",
        )
    return PublicScanStatusResponse(**payload)
