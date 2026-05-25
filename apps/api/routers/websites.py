from __future__ import annotations

import logging
import os
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.quota import check_website_quota, violation_to_dict
from apps.api.database import get_db
from apps.api.pagination import page_meta
from apps.api.models.enums import VerificationStatus
from apps.api.models.user import User
from apps.api.target_validation import TargetRejected, validate_target
from apps.api.schemas.websites import (
    WebsiteCreate,
    WebsiteListResponse,
    WebsitePatch,
    WebsiteResponse,
)
from apps.api.security import get_current_user
from apps.api.services import websites as ws_service
from apps.api.services import verification as verify_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/websites", tags=["websites"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("", response_model=WebsiteResponse, status_code=201)
async def create_website(
    data: WebsiteCreate, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    if not current_user.is_admin:
        violation = await check_website_quota(db, current_user)
        if violation is not None:
            raise HTTPException(status_code=402, detail=violation_to_dict(violation))
    # Block obviously-internal targets at the entry point. Defense-in-depth:
    # scan_jobs revalidates on submit, and the worker rejects again at scan
    # time if DNS resolves to a private IP.
    try:
        validate_target(str(data.url))
    except TargetRejected as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": exc.code, "message": exc.reason},
        )
    try:
        website = await ws_service.create_website(db, data, user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ws_service.DuplicateWebsiteError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    await db.commit()
    return WebsiteResponse.model_validate(website)


@router.get("", response_model=WebsiteListResponse)
async def list_websites(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    verification_status: VerificationStatus | None = None,
    hostname: str | None = None,
) -> WebsiteListResponse:
    items, total = await ws_service.list_websites(
        db,
        limit=limit,
        offset=offset,
        verification_status=verification_status,
        hostname=hostname,
        user_id=_uid(current_user),
    )
    return WebsiteListResponse(
        items=[WebsiteResponse.model_validate(w) for w in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{website_id}", response_model=WebsiteResponse)
async def get_website(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return WebsiteResponse.model_validate(website)


@router.patch("/{website_id}", response_model=WebsiteResponse)
async def patch_website(
    website_id: uuid.UUID, data: WebsitePatch, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    website = await ws_service.update_website(
        db, website_id, data, user_id=_uid(current_user)
    )
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    await db.commit()
    return WebsiteResponse.model_validate(website)


@router.delete("/{website_id}", status_code=204)
async def delete_website(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> None:
    deleted = await ws_service.delete_website(
        db, website_id, user_id=_uid(current_user)
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Website not found")
    await db.commit()


# ── Domain Verification ───────────────────────────────────────────────────────

from apps.api.models.enums import VerificationMethod  # noqa: E402


@router.post("/{website_id}/verify/initiate")
async def initiate_verification(
    website_id: uuid.UUID,
    method: VerificationMethod,
    db: _DB,
    current_user: _CurrentUser,
) -> dict:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    if website.verification_status.value == "verified":
        logger.info(
            "verify-initiate: website=%s already verified", website.hostname,
        )
        return {"already_verified": True}
    # Admin bypass is now opt-in via ADMIN_VERIFY_BYPASS=1 env var.
    # Previously admins were silently auto-verified, which prevented the
    # real DNS flow from being tested by the team that owns the product.
    if current_user.is_admin and os.getenv("ADMIN_VERIFY_BYPASS") == "1":
        logger.warning(
            "verify-initiate: ADMIN_VERIFY_BYPASS for %s by %s",
            website.hostname, current_user.email,
        )
        website.verification_status = VerificationStatus.VERIFIED
        await db.commit()
        return {"already_verified": True}
    dv = await verify_service.get_or_create_verification(db, website, method)
    await db.commit()
    return {
        "method": method.value,
        "token": dv.token,
        "hostname": website.hostname,
        "url": website.url,
    }


@router.post("/{website_id}/verify/check")
async def check_verification(
    website_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
) -> dict:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    if website.verification_status.value == "verified":
        # Short-circuit — already marked verified by a previous successful
        # check (or admin bypass). Logging this so the user can tell the
        # difference between "really verified now" and "verified earlier".
        logger.info(
            "verify-check: website=%s SHORT-CIRCUIT (already verified)",
            website.hostname,
        )
        return {"verified": True}
    dv = await verify_service.get_pending_verification(db, website_id)
    if dv is None:
        raise HTTPException(400, "No pending verification. Please initiate first.")
    verified = await verify_service.check_verification(db, website, dv)
    await db.commit()
    return {"verified": verified}


@router.get("/{website_id}/verify")
async def get_verification_status(
    website_id: uuid.UUID,
    db: _DB,
    current_user: _CurrentUser,
) -> dict:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    dv = await verify_service.get_pending_verification(db, website_id)
    return {
        "verification_status": website.verification_status.value,
        "pending_method": dv.method.value if dv else None,
        "pending_token": dv.token if dv else None,
    }
