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
from apps.api.models.user import User
from apps.api.security import get_current_user
from apps.api.services.public_scan import (
    ClaimError,
    PublicScanError,
    check_ip_rate_limit,
    claim_guest_scan,
    create_guest_scan,
    get_guest_scan_status,
)

router = APIRouter(prefix="/public/scan", tags=["public-scan"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


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


# ---------------------------------------------------------------------------
# Slice 4.C — Save my report. Authenticated; called by the front-
# end immediately after a successful POST /auth/register so the
# guest scan is migrated to the new user atomically.
# ---------------------------------------------------------------------------


class PublicScanClaimResponse(BaseModel):
    scan_id: str
    guest_token: str
    website_id: str
    status: str
    target_url: str


@router.post(
    "/{guest_token}/claim",
    response_model=PublicScanClaimResponse,
)
async def claim_public_scan(
    guest_token: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
) -> PublicScanClaimResponse:
    """Attach a guest scan to the authenticated caller's account.
    Idempotent — re-claiming the same scan returns the same
    payload. 400 with a plain-English detail on validation
    failure; 401 if the caller isn't authenticated (handled by
    the dependency)."""
    try:
        payload = await claim_guest_scan(
            db, guest_token=guest_token, user_id=current_user.id,
        )
    except ClaimError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    return PublicScanClaimResponse(**payload)


# ---------------------------------------------------------------------------
# Slice 4.B — Server-Sent Events stream filtered to this scan_job
# (via target_id on the published event). Mirrors the pattern in
# apps/api/internal/alerts.py:event_stream. Unauthenticated — the
# guest_token is the entire access credential.
# ---------------------------------------------------------------------------


import asyncio       # noqa: E402

import redis.asyncio as aioredis      # noqa: E402
from fastapi.responses import StreamingResponse   # noqa: E402

from apps.api.config import get_settings    # noqa: E402
from apps.api.telemetry import EVENT_CHANNEL    # noqa: E402


@router.get("/{guest_token}/events")
async def scan_events_stream(
    guest_token: uuid.UUID,
    request: Request,
    db: _DB,
) -> StreamingResponse:
    """Live scan-progress events for the guest scan identified by
    token. The front-end opens this via EventSource; the polling
    status page can keep working as a fallback when SSE is
    unavailable.

    Subscription model: we subscribe to the platform-wide
    EVENT_CHANNEL and filter to this scan_job's events client-side.
    That keeps the Redis subscriber footprint small (1 pubsub
    channel for the whole platform) at the cost of a tiny CPU
    filter per frame.

    Auth: token-only. We resolve the token → scan_job_id once at
    subscription, then filter every published event by
    target_id == scan_job_id. An unknown token returns 404
    *before* the SSE stream opens so attackers can't guess via
    long-poll timing.
    """
    # Translate token → scan_id (and 404 cleanly if unknown).
    payload = await get_guest_scan_status(db, guest_token)
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="That scan link isn’t recognised. It may have expired.",
        )
    scan_job_id = payload["scan_id"]
    settings = get_settings()

    async def gen():
        r = None
        pubsub = None
        try:
            r = aioredis.from_url(
                settings.redis_url,
                socket_connect_timeout=2,
                decode_responses=True,
            )
            pubsub = r.pubsub()
            await pubsub.subscribe(EVENT_CHANNEL)
            # First frame: 'connected' comment so the client can flip
            # its UI out of the 'waiting for connection' state.
            yield ": connected\n\n"
            # Snapshot frame: send the current status so the client
            # doesn't wait for the next worker event to render
            # anything meaningful.
            import json as _json
            yield f"event: snapshot\ndata: {_json.dumps(payload)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=15,
                    )
                except Exception:  # noqa: BLE001
                    break
                if msg and msg.get("type") == "message":
                    raw = msg.get("data") or ""
                    # Filter to this scan_job's events only.
                    try:
                        evt = _json.loads(raw)
                    except Exception:  # noqa: BLE001
                        continue
                    if (evt.get("target_type") == "scan_job"
                            and evt.get("target_id") == scan_job_id):
                        yield f"data: {raw}\n\n"
                        if evt.get("kind") in ("scan.completed", "scan.failed"):
                            break
                else:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                if pubsub is not None:
                    await pubsub.unsubscribe(EVENT_CHANNEL)
                    await pubsub.aclose()
                if r is not None:
                    await r.aclose()
            except Exception:  # noqa: BLE001
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
