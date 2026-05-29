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


def _denylist_key(user_id: uuid.UUID | str) -> str:
    return f"auth:denylist:{user_id}"


async def _is_denylisted(user_id: uuid.UUID) -> bool:
    """Best-effort Redis check; if Redis is unreachable we fall open (is_active
    is the durable backstop). Staff use this to force-logout all sessions for
    a user without rotating the JWT secret."""
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            return bool(await r.exists(_denylist_key(user_id)))
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        return False


async def denylist_user(user_id: uuid.UUID, *, ttl_seconds: int | None = None) -> None:
    """Revoke every outstanding token for `user_id`. TTL defaults to the JWT
    expiry so the denylist entry doesn't outlive any token it could block."""
    settings = get_settings()
    ttl = ttl_seconds or max(settings.access_token_expire_minutes * 60, 60)
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=1)
        try:
            await r.set(_denylist_key(user_id), "1", ex=ttl)
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        pass


async def denylist_clear(user_id: uuid.UUID) -> None:
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            await r.delete(_denylist_key(user_id))
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        pass


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
    if await _is_denylisted(user_id):
        raise HTTPException(status_code=401, detail="Session revoked")
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


# ---------------------------------------------------------------------------
# Phase-4 active-org context resolution
# ---------------------------------------------------------------------------


async def get_active_org_id(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    x_org_id: Annotated[
        str | None,
        # FastAPI maps ``X-Org-Id`` header to this parameter via the
        # Header() dependency. Default lives on the parameter, not
        # inside Header() — FastAPI rejects default-inside-Annotated.
        __import__("fastapi").Header(alias="X-Org-Id"),
    ] = None,
) -> uuid.UUID | None:
    """Resolve the caller's currently-active org for tenant-scoped queries.

    Returns:
      * ``None`` when no ``X-Org-Id`` header is set — single-tenant
        legacy behaviour. Services that accept ``active_org_id=None``
        will return *all* visible rows (the OR-NULL branch of the
        tenant filter), preserving today's UX while the org switcher
        rolls out incrementally.
      * The supplied UUID when the user has an accepted membership in
        that org. The downstream list queries restrict to
        ``(col IS NULL) OR (col = active_org_id)`` so legacy rows
        remain visible alongside the tenant's own rows.

    Raises:
      * ``HTTPException(400)`` when the header is malformed.
      * ``HTTPException(403)`` when the header references a real
        UUID but the user is NOT a member — never silently fall back
        to None, that would leak rows.
    """
    if not x_org_id:
        return None
    try:
        org_id = uuid.UUID(x_org_id)
    except ValueError:
        raise HTTPException(status_code=400,
                             detail="X-Org-Id is not a valid UUID")
    # Lazy import — keeps security.py free of model imports at module
    # load time so the JWT path stays cheap.
    from apps.api.services.orgs import get_membership
    membership = await get_membership(
        db, org_id=org_id, user_id=current_user.id,
    )
    if membership is None:
        raise HTTPException(
            status_code=403,
            detail="not a member of this org",
        )
    return org_id
