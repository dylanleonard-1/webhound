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
from apps.api.schemas.auth import (
    LoginChallengeResponse,
    LoginResendRequest,
    LoginVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from apps.api.security import (
    create_access_token,
    create_login_challenge_token,
    decode_login_challenge_token,
    get_current_user,
)
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
    # Account creation issues a session immediately so users land in the
    # verify-email flow signed in. Subsequent explicit logins go through the
    # email-OTP challenge.
    body = UserResponse.model_validate(user).model_dump(mode="json")
    body["access_token"] = create_access_token(user.id)
    body["token_type"] = "bearer"
    if dev_link:
        body["dev_verify_url"] = dev_link
    return JSONResponse(content=body, status_code=201)


@router.post("/login", response_model=LoginChallengeResponse)
async def login(data: UserLogin, db: _DB) -> LoginChallengeResponse:
    # Step 1 of 2: validate password, issue a 6-digit email code, and return a
    # short-lived challenge token. The client posts the challenge back to
    # /auth/login/verify along with the code to receive the JWT.
    user = await auth_service.authenticate_user(db, data.email, data.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    dev_code = await auth_service.issue_login_otp(db, user)
    await db.commit()
    challenge, ttl = create_login_challenge_token(user.id)
    response = LoginChallengeResponse(
        challenge_token=challenge,
        email=auth_service.mask_email(user.email),
        expires_in=ttl,
    )
    if dev_code:
        # Surface the code in dev mode so testers don't have to dig through logs.
        return JSONResponse(
            content={**response.model_dump(), "dev_code": dev_code},
            status_code=200,
        )
    return response


@router.post("/login/verify", response_model=TokenResponse)
async def login_verify(data: LoginVerifyRequest, db: _DB) -> TokenResponse:
    user_id = decode_login_challenge_token(data.challenge_token)
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account not found or inactive")
    try:
        await auth_service.verify_login_otp(db, user, data.code)
    except auth_service.InvalidLoginCodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    return TokenResponse(access_token=create_access_token(user.id))


@router.post("/login/resend-code")
async def login_resend_code(data: LoginResendRequest, db: _DB) -> dict:
    user_id = decode_login_challenge_token(data.challenge_token)
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account not found or inactive")
    dev_code = await auth_service.issue_login_otp(db, user)
    await db.commit()
    result: dict = {"message": "Code resent"}
    if dev_code:
        result["dev_code"] = dev_code
    return result


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


@router.post("/forgot-password")
async def forgot_password(data: PasswordResetRequest, db: _DB) -> dict:
    # Always returns the same success message regardless of whether the email
    # exists — prevents account enumeration.
    dev_link = await auth_service.request_password_reset(db, data.email)
    await db.commit()
    response: dict = {
        "message": "If an account exists for that email, a reset link has been sent."
    }
    if dev_link:
        response["dev_reset_url"] = dev_link
    return response


@router.post("/reset-password")
async def reset_password(data: PasswordResetConfirm, db: _DB) -> dict:
    try:
        await auth_service.reset_password(db, data.token, data.new_password)
    except auth_service.InvalidResetTokenError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    return {"message": "Password reset successfully. You can now sign in."}
