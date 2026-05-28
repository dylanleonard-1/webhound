# WebHound — apps/api/services/deployments.py
# Deploy history. The Railway-injected RAILWAY_GIT_COMMIT_SHA is the source of
# truth for what's running right now; this records who shipped what, when.

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.deployment import Deployment

VALID_SERVICES = ("api", "worker", "web", "scanner", "other")
VALID_STATUSES = ("in_progress", "succeeded", "failed", "rolled_back")


def current_sha() -> str | None:
    """The commit currently running on whatever service this code is in.

    Railway injects RAILWAY_GIT_COMMIT_SHA per service deploy. Returns None
    if it isn't set (e.g. local dev), which the UI surfaces as 'unknown'.
    """
    return os.getenv("RAILWAY_GIT_COMMIT_SHA")


async def record(
    db: AsyncSession, *,
    service: str, sha: str, status: str = "succeeded",
    actor_email: str | None, note: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> Deployment:
    if service not in VALID_SERVICES:
        raise ValueError(f"Invalid service: {service}")
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if len(sha) < 7:
        raise ValueError("sha must be at least 7 chars")
    now = datetime.now(timezone.utc)
    dep = Deployment(
        service=service, sha=sha.strip(), status=status, actor_email=actor_email,
        note=note, started_at=started_at or now,
        finished_at=finished_at or (now if status in ("succeeded", "failed", "rolled_back") else None),
    )
    db.add(dep)
    await db.flush()
    return dep


async def list_recent(db: AsyncSession, *, service: str | None = None,
                     limit: int = 50) -> list[dict]:
    q = select(Deployment)
    if service:
        q = q.where(Deployment.service == service)
    q = q.order_by(Deployment.started_at.desc()).limit(limit)
    rows = await db.scalars(q)
    return [
        {
            "id": str(d.id), "service": d.service, "sha": d.sha,
            "status": d.status, "actor": d.actor_email, "note": d.note,
            "started_at": d.started_at.isoformat() if d.started_at else None,
            "finished_at": d.finished_at.isoformat() if d.finished_at else None,
        }
        for d in rows.all()
    ]
