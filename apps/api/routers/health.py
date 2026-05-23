from __future__ import annotations

import os
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/health/version")
async def health_version(request: Request) -> dict:
    # Railway exposes the deployed commit as RAILWAY_GIT_COMMIT_SHA. Surface
    # it (plus a snapshot of auth routes) so we can verify what's actually
    # running on prod without shell access.
    sha = (
        os.getenv("RAILWAY_GIT_COMMIT_SHA")
        or os.getenv("GIT_COMMIT_SHA")
        or "unknown"
    )
    auth_routes = sorted(
        getattr(r, "path", "")
        for r in request.app.routes
        if getattr(r, "path", "").startswith("/auth")
    )
    return {
        "commit": sha[:12] if sha != "unknown" else sha,
        "auth_routes": auth_routes,
    }


@router.get("/health/db")
async def health_db(db: Annotated[AsyncSession, Depends(get_db)]) -> dict:
    try:
        await db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"
    return {"status": "ok", "database": db_status}


@router.get("/health/worker")
async def health_worker() -> dict:
    settings = get_settings()
    try:
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        broker_status = "ok"
    except Exception as exc:
        broker_status = f"error: {exc}"
    return {"status": "ok", "broker": broker_status}
