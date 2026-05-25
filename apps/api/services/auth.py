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
    EmailDeliveryResult,
    send_login_code_email,
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
    # New registrations always agree to T&C in the form before they can
    # submit (Register form checkbox + server-side validation). Record the
    # timestamp so they don't get sent through /agreement again later.
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        is_active=True,
        is_admin=is_admin,
        full_name=data.full_name,
        company_name=data.company_name,
        use_case=data.use_case,
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=expires,
        terms_agreed_at=datetime.now(timezone.utc),
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


class InvalidLoginCodeError(Exception):
    pass


def mask_email(email: str) -> str:
    if "@" not in email:
        return email
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


_LOGIN_OTP_TTL_MINUTES = 10


async def issue_login_otp(db: AsyncSession, user: User) -> EmailDeliveryResult:
    # Stores a 6-digit OTP on the user row, emails it, and returns the
    # delivery result. Callers use this to decide whether to surface a
    # dev_code / delivery hint to the client.
    code = f"{secrets.randbelow(10**6):06d}"
    user.login_otp = code
    user.login_otp_expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=_LOGIN_OTP_TTL_MINUTES)
    )
    await db.flush()
    result = await send_login_code_email(user.email, code)
    # Safety net for admins only when email delivery actually fails — so we
    # don't get locked out by a Resend outage. On a successful send the code
    # stays out of the API response.
    if user.is_admin and not result.delivered and result.dev_value is None:
        result.dev_value = code
    return result


async def verify_login_otp(db: AsyncSession, user: User, code: str) -> bool:
    if not user.login_otp or not user.login_otp_expires_at:
        raise InvalidLoginCodeError("No active login code. Please sign in again.")
    expires = user.login_otp_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        raise InvalidLoginCodeError("This code has expired. Please sign in again.")
    if not secrets.compare_digest(user.login_otp, code):
        raise InvalidLoginCodeError("Incorrect code.")
    user.login_otp = None
    user.login_otp_expires_at = None
    await db.flush()
    return True


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
