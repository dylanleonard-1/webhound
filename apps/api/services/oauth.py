from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.user import User


@dataclass
class OAuthUserInfo:
    provider: str
    provider_id: str
    email: str | None
    name: str | None
    avatar_url: str | None


async def find_or_create_oauth_user(db: AsyncSession, info: OAuthUserInfo) -> User:
    admin_emails = get_settings().admin_emails
    # 1. Find by provider + provider_id (returning user)
    user = await db.scalar(
        sa.select(User).where(
            User.oauth_provider == info.provider,
            User.oauth_provider_id == info.provider_id,
        )
    )
    if user:
        if user.email and user.email.strip().lower() in admin_emails and not user.is_admin:
            user.is_admin = True
        return user

    # 2. Find by email and link OAuth to existing account
    if info.email:
        user = await db.scalar(sa.select(User).where(User.email == info.email))
        if user:
            user.oauth_provider = info.provider
            user.oauth_provider_id = info.provider_id
            user.email_verified = True  # provider already verified the email
            if info.name and not user.full_name:
                user.full_name = info.name
            if info.avatar_url and not user.avatar_url:
                user.avatar_url = info.avatar_url
            if info.email.strip().lower() in admin_emails and not user.is_admin:
                user.is_admin = True
            return user

    # 3. Create new OAuth user (email already verified by provider)
    email = info.email or f"{info.provider}_{info.provider_id}@webhound.oauth"
    is_admin = email.strip().lower() in admin_emails
    user = User(
        email=email,
        hashed_password=None,
        oauth_provider=info.provider,
        oauth_provider_id=info.provider_id,
        full_name=info.name,
        avatar_url=info.avatar_url,
        is_active=True,
        is_admin=is_admin,
        email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user
