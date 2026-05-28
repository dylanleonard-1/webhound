# WebHound — apps/api/internal/abuse.py
# Phase 5: Fraud & Abuse — flag triage (list/detail/dismiss/escalate-to-ban),
# ad-hoc evaluation, summary for the nav badge, and per-customer fingerprints.

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.abuse import AbuseFlag
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.services import customers as cust_svc
from apps.api.services import fraud as fraud_svc

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _DismissBody(BaseModel):
    note: str | None = None


class _BanBody(BaseModel):
    reason: str | None = None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


def _flag_dict(f: AbuseFlag) -> dict:
    return {
        "id": str(f.id),
        "dedup_key": f.dedup_key,
        "user_id": str(f.user_id) if f.user_id else None,
        "ip_address": f.ip_address,
        "score": f.score,
        "severity": f.severity,
        "status": f.status,
        "reasons": list(f.reasons or []),
        "occurrences": f.occurrences,
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "resolved_by": f.resolved_by_email,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "resolution_note": f.resolution_note,
    }


@router.get("/abuse/flags")
async def list_flags(
    admin: _Read, db: _DB,
    status: str | None = None,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    base = select(AbuseFlag)
    count_base = select(func.count()).select_from(AbuseFlag)
    if status:
        base = base.where(AbuseFlag.status == status)
        count_base = count_base.where(AbuseFlag.status == status)
    if severity:
        base = base.where(AbuseFlag.severity == severity)
        count_base = count_base.where(AbuseFlag.severity == severity)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(AbuseFlag.last_seen_at.desc()).limit(limit).offset(offset)
    )
    return {"items": [_flag_dict(f) for f in rows.all()],
            "total": int(total), "limit": limit, "offset": offset}


@router.get("/abuse/summary")
async def abuse_summary(admin: _Read, db: _DB) -> dict:
    """Open-flag counts by severity for the nav badge."""
    rows = await db.execute(
        select(AbuseFlag.severity, func.count())
        .where(AbuseFlag.status == "pending")
        .group_by(AbuseFlag.severity)
    )
    by_sev = {str(s): int(n) for s, n in rows.all()}
    return {"pending": sum(by_sev.values()), "by_severity": by_sev}


@router.get("/abuse/flags/{flag_id}")
async def flag_detail(flag_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    flag = await db.get(AbuseFlag, flag_id)
    if flag is None:
        raise HTTPException(status_code=404, detail="Flag not found")
    out = _flag_dict(flag)
    out["detail"] = dict(flag.detail or {})
    # Enrich with the subject's email when present.
    if flag.user_id:
        u = await db.get(User, flag.user_id)
        out["user_email"] = u.email if u else None
        out["user_is_active"] = bool(u and u.is_active)
    return out


async def _load(db: AsyncSession, flag_id: uuid.UUID) -> AbuseFlag:
    flag = await db.get(AbuseFlag, flag_id)
    if flag is None:
        raise HTTPException(status_code=404, detail="Flag not found")
    return flag


@router.post("/abuse/flags/{flag_id}/dismiss")
async def dismiss_flag(flag_id: uuid.UUID, body: _DismissBody, admin: _Op, db: _DB,
                       request: Request) -> dict:
    flag = await _load(db, flag_id)
    await fraud_svc.dismiss(db, flag, actor_email=admin.email, note=body.note)
    await record_action(db, actor=admin, action="abuse.dismiss",
                        target_type="abuse_flag", target_id=str(flag_id),
                        detail={"note": body.note}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": "dismissed"}


@router.post("/abuse/flags/{flag_id}/ban")
async def ban_from_flag(flag_id: uuid.UUID, body: _BanBody, admin: _Admin, db: _DB,
                        request: Request) -> dict:
    flag = await _load(db, flag_id)
    if flag.user_id is None:
        raise HTTPException(status_code=400, detail="Cannot ban an IP-only flag here")
    user = await db.get(User, flag.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Flagged user no longer exists")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot ban yourself")
    reason = body.reason or f"Abuse flag {flag_id}: {', '.join(flag.reasons or [])}"
    await cust_svc.suspend(db, user, reason=reason)
    await fraud_svc.mark_banned(db, flag, actor_email=admin.email)
    await record_action(db, actor=admin, action="abuse.ban",
                        target_type="user", target_id=str(user.id),
                        detail={"flag_id": str(flag_id), "reason": reason},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "status": "banned"}


@router.post("/abuse/evaluate/{user_id}")
async def evaluate_one(user_id: uuid.UUID, admin: _Op, db: _DB,
                       request: Request) -> dict:
    """Ad-hoc trigger — score this user now and upsert/dismiss the flag."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    score = await fraud_svc.evaluate_user(db, user_id, email=user.email)
    out: dict = {"score": score}
    if score["score"] >= fraud_svc.FLAG_THRESHOLD:
        flag, created = await fraud_svc.upsert_flag(
            db, user_id=user_id, ip_address=None,
            score=score["score"], severity=score["severity"],
            reasons=score["reasons"], detail=score["detail"],
        )
        out["flag_id"] = str(flag.id)
        out["flag_created"] = created
        await record_action(db, actor=admin, action="abuse.evaluate",
                            target_type="user", target_id=str(user_id),
                            detail={"score": score["score"], "created": created},
                            **_audit_ctx(request))
    await db.commit()
    return out


@router.get("/customers/{user_id}/fingerprints")
async def customer_fingerprints(user_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    return {"items": await fraud_svc.list_fingerprints(db, user_id)}
