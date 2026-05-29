from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api._url_utils import URLValidationError, normalize_url
from apps.api.models.enums import VerificationStatus
from apps.api.models.website import Website
from apps.api.schemas.websites import WebsiteCreate, WebsitePatch


class DuplicateWebsiteError(Exception):
    pass


async def create_website(
    db: AsyncSession, data: WebsiteCreate, user_id: uuid.UUID | None = None
) -> Website:
    try:
        normalized_url, scheme, hostname = normalize_url(data.url)
    except URLValidationError as exc:
        raise ValueError(str(exc)) from exc

    existing = await db.scalar(
        sa.select(Website).where(Website.url == normalized_url)
    )
    if existing is not None:
        raise DuplicateWebsiteError(
            f"A website with this URL already exists: {normalized_url}"
        )

    website = Website(
        url=normalized_url,
        hostname=hostname,
        scheme=scheme,
        display_name=data.display_name,
        verification_status=VerificationStatus.UNVERIFIED,
        user_id=user_id,
    )
    db.add(website)
    await db.flush()
    await db.refresh(website)
    return website


async def get_website(
    db: AsyncSession, website_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> Website | None:
    if user_id is None:
        return await db.get(Website, website_id)
    return await db.scalar(
        sa.select(Website).where(
            Website.id == website_id, Website.user_id == user_id
        )
    )


async def list_websites(
    db: AsyncSession,
    *,
    limit: int = 20,
    offset: int = 0,
    verification_status: VerificationStatus | None = None,
    hostname: str | None = None,
    user_id: uuid.UUID | None = None,
    active_org_id: uuid.UUID | None = None,
) -> tuple[list[Website], int]:
    from apps.api.services.tenant import apply_org_scope

    base = sa.select(Website)
    count_base = sa.select(sa.func.count()).select_from(Website)

    if user_id is not None:
        base = base.where(Website.user_id == user_id)
        count_base = count_base.where(Website.user_id == user_id)

    if verification_status is not None:
        base = base.where(Website.verification_status == verification_status)
        count_base = count_base.where(
            Website.verification_status == verification_status
        )

    if hostname:
        pattern = f"%{hostname}%"
        base = base.where(Website.hostname.ilike(pattern))
        count_base = count_base.where(Website.hostname.ilike(pattern))

    # Phase-4 tenancy scope. Legacy NULL rows always pass.
    base = apply_org_scope(base, Website.org_id, active_org_id)
    count_base = apply_org_scope(count_base, Website.org_id, active_org_id)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(Website.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def update_website(
    db: AsyncSession,
    website_id: uuid.UUID,
    data: WebsitePatch,
    user_id: uuid.UUID | None = None,
) -> Website | None:
    website = await get_website(db, website_id, user_id)
    if website is None:
        return None

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(website, field, value)

    await db.flush()
    await db.refresh(website)
    return website


async def delete_website(
    db: AsyncSession, website_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> bool:
    website = await get_website(db, website_id, user_id)
    if website is None:
        return False
    await db.delete(website)
    await db.flush()
    return True
