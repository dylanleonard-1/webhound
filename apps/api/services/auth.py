from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.user import User
from apps.api.schemas.auth import UserCreate
from apps.api.security import hash_password, verify_password
from apps.api.services.email import send_verification_email


class DuplicateEmailError(Exception):
    pass


def _make_verification_token() -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    return token, expires


async def create_user(db: AsyncSession, data: UserCreate) -> User:
    existing = await db.scalar(sa.select(User).where(User.email == data.email))
    if existing is not None:
        raise DuplicateEmailError(f"Email already registered: {data.email}")
    token, expires = _make_verification_token()
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        is_active=True,
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=expires,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await send_verification_email(user.email, token)
    return user


async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> User | None:
    user = await db.scalar(sa.select(User).where(User.email == email))
    if user is None or user.hashed_password is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user
