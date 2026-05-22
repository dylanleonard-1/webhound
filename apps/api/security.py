from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.models.user import User

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(user_id: uuid.UUID) -> str:
    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    return jwt.encode(
        {"sub": str(user_id), "exp": expires},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


_LOGIN_CHALLENGE_TTL_SECONDS = 10 * 60


def create_login_challenge_token(user_id: uuid.UUID) -> tuple[str, int]:
    # Short-lived signed token returned after a successful password step.
    # Holds purpose="login_otp" so an attacker can't use it as a real session.
    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(seconds=_LOGIN_CHALLENGE_TTL_SECONDS)
    token = jwt.encode(
        {"sub": str(user_id), "exp": expires, "purpose": "login_otp"},
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    return token, _LOGIN_CHALLENGE_TTL_SECONDS


def decode_login_challenge_token(token: str) -> uuid.UUID:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired login challenge") from exc
    if payload.get("purpose") != "login_otp":
        raise HTTPException(status_code=401, detail="Invalid login challenge")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid login challenge")
    try:
        return uuid.UUID(sub)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid login challenge") from exc


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    settings = get_settings()
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user
