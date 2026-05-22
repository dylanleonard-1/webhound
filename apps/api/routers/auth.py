from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.schemas.auth import TokenResponse, UserCreate, UserLogin, UserResponse
from apps.api.security import create_access_token, get_current_user
from apps.api.services import auth as auth_service
from apps.api.services.email import send_verification_email

router = APIRouter(prefix="/auth", tags=["auth"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("/register", status_code=201)
async def register(data: UserCreate, db: _DB) -> JSONResponse:
    try:
        user, dev_link = await auth_service.create_user(db, data)
    except auth_service.DuplicateEmailError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    await db.commit()
    body = UserResponse.model_validate(user).model_dump(mode="json")
    if dev_link:
        body["dev_verify_url"] = dev_link
    return JSONResponse(content=body, status_code=201)


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: _DB) -> TokenResponse:
    user = await auth_service.authenticate_user(db, data.email, data.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return TokenResponse(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserResponse)
async def me(current_user: _CurrentUser) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.get("/verify-email")
async def verify_email(token: str, db: _DB) -> dict:
    user = await db.scalar(
        sa.select(User).where(User.email_verification_token == token)
    )
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    if user.email_verified:
        return {"message": "Email already verified"}
    now = datetime.now(timezone.utc)
    if user.email_verification_expires_at and user.email_verification_expires_at < now:
        raise HTTPException(status_code=400, detail="Verification token has expired")
    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_expires_at = None
    await db.commit()
    return {"message": "Email verified successfully"}


@router.post("/resend-verification")
async def resend_verification(current_user: _CurrentUser, db: _DB) -> dict:
    if current_user.email_verified:
        raise HTTPException(status_code=400, detail="Email is already verified")
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    current_user.email_verification_token = token
    current_user.email_verification_expires_at = expires
    await db.commit()
    dev_link = await send_verification_email(current_user.email, token)
    result: dict = {"message": "Verification email sent"}
    if dev_link:
        result["dev_verify_url"] = dev_link
    return result
