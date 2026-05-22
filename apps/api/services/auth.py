from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.user import User
from apps.api.schemas.auth import UserCreate
from apps.api.security import hash_password, verify_password
from apps.api.services.email import (
    send_password_reset_email,
    send_verification_email,
)


class DuplicateEmailError(Exception):
    pass


def _make_verification_token() -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    return token, expires


async def create_user(db: AsyncSession, data: UserCreate) -> tuple[User, str | None]:
    existing = await db.scalar(sa.select(User).where(User.email == data.email))
    if existing is not None:
        raise DuplicateEmailError(f"Email already registered: {data.email}")
    token, expires = _make_verification_token()
    is_admin = data.email.strip().lower() in get_settings().admin_emails
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        is_active=True,
        is_admin=is_admin,
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=expires,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    dev_link = await send_verification_email(user.email, token)
    return user, dev_link


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


class InvalidResetTokenError(Exception):
    pass


async def request_password_reset(db: AsyncSession, email: str) -> str | None:
    # Always returns successfully to avoid leaking which emails are registered.
    # Returns dev-mode reset link when no email provider is configured.
    user = await db.scalar(sa.select(User).where(User.email == email))
    if user is None or user.hashed_password is None:
        return None
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    user.password_reset_token = token
    user.password_reset_expires_at = expires
    await db.flush()
    return await send_password_reset_email(user.email, token)


async def reset_password(db: AsyncSession, token: str, new_password: str) -> User:
    user = await db.scalar(
        sa.select(User).where(User.password_reset_token == token)
    )
    if user is None:
        raise InvalidResetTokenError("Invalid or expired reset token")
    expires = user.password_reset_expires_at
    if expires is None:
        raise InvalidResetTokenError("Invalid or expired reset token")
    # SQLite drops tzinfo on round-trip; treat naive as UTC.
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        raise InvalidResetTokenError("Invalid or expired reset token")
    user.hashed_password = hash_password(new_password)
    user.password_reset_token = None
    user.password_reset_expires_at = None
    await db.flush()
    return user
