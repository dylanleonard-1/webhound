"""Regression: owned websites must always be created with an org_id.

Production hit a 500 on ``POST /websites`` because ``create_website`` set
``user_id`` but left ``org_id`` NULL, violating the DB check constraint
``chk_websites_owned_has_org`` (``user_id IS NULL OR org_id IS NOT NULL``).
The fix resolves/creates the owner's personal org and stamps ``org_id``.

These tests exercise the service layer directly (no HTTP / Redis), so they
stay fast and isolated from the rate-limit middleware.
"""
from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401
from apps.api.database import Base
from apps.api.models.enums import PlanTier
from apps.api.models.org import Org, OrgMembership
from apps.api.models.enums import OrgRole
from apps.api.models.user import User
from apps.api.schemas.websites import WebsiteCreate
from apps.api.services import websites as ws_service
from apps.api.services.orgs import ensure_personal_org

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


async def _make_user(session: AsyncSession) -> User:
    user = User(
        email=f"u{uuid.uuid4().hex[:8]}@example.com",
        is_active=True,
        plan=PlanTier.FREE,
    )
    session.add(user)
    await session.flush()
    return user


async def test_create_website_sets_org_id_to_personal_org(session: AsyncSession):
    user = await _make_user(session)

    website = await ws_service.create_website(
        session, WebsiteCreate(url="https://example.com"), user_id=user.id
    )

    # The bug: org_id was None here.
    assert website.org_id is not None
    assert website.user_id == user.id

    org = await session.get(Org, website.org_id)
    assert org is not None
    assert org.slug == f"personal-{user.id.hex}"

    membership = await session.scalar(
        sa.select(OrgMembership).where(
            OrgMembership.org_id == org.id,
            OrgMembership.user_id == user.id,
        )
    )
    assert membership is not None
    assert membership.role == OrgRole.OWNER
    assert membership.accepted_at is not None


async def test_create_website_reuses_existing_personal_org(session: AsyncSession):
    user = await _make_user(session)

    w1 = await ws_service.create_website(
        session, WebsiteCreate(url="https://one.example.com"), user_id=user.id
    )
    w2 = await ws_service.create_website(
        session, WebsiteCreate(url="https://two.example.com"), user_id=user.id
    )

    assert w1.org_id == w2.org_id
    # Exactly one personal org for the user — no duplicates.
    orgs = (
        await session.scalars(
            sa.select(Org).where(Org.slug == f"personal-{user.id.hex}")
        )
    ).all()
    assert len(orgs) == 1


async def test_create_website_honours_explicit_active_org(session: AsyncSession):
    user = await _make_user(session)
    # A real org the caller is acting within (e.g. via X-Org-Id).
    org = await ensure_personal_org(session, user.id)

    website = await ws_service.create_website(
        session,
        WebsiteCreate(url="https://team.example.com"),
        user_id=user.id,
        org_id=org.id,
    )
    assert website.org_id == org.id


async def test_guest_website_stays_org_less(session: AsyncSession):
    # Admin-imported / guest pattern: user_id None → org_id stays None,
    # which the constraint permits. Must NOT spuriously create an org.
    website = await ws_service.create_website(
        session, WebsiteCreate(url="https://guest.example.com"), user_id=None
    )
    assert website.user_id is None
    assert website.org_id is None


async def test_ensure_personal_org_is_idempotent(session: AsyncSession):
    user = await _make_user(session)
    a = await ensure_personal_org(session, user.id)
    b = await ensure_personal_org(session, user.id)
    assert a.id == b.id
    memberships = (
        await session.scalars(
            sa.select(OrgMembership).where(OrgMembership.user_id == user.id)
        )
    ).all()
    assert len(memberships) == 1
