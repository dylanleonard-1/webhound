# WebHound — apps/api/tests/test_tenant_scoping.py
# Phase-4 slice 2: query-scope helper + list-service org filtering.
#
# Invariants under test:
#   1. active_org_id=None never restricts anything (single-tenant legacy).
#   2. active_org_id=X returns rows where org_id IS NULL OR org_id = X.
#      The NULL branch is what keeps legacy rows visible during the
#      additive scaffold phase.
#   3. active_org_id=X never returns rows belonging to a *different* org.

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.enums import (
    PlanTier, ScanStatus, VerificationStatus,
)
from apps.api.models.org import Org
from apps.api.models.scan_job import ScanJob
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import hash_password
from apps.api.services.scan_jobs import list_scan_jobs
from apps.api.services.tenant import apply_org_scope, org_scope_filter
from apps.api.services.websites import list_websites


pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helper unit tests (no DB)
# ---------------------------------------------------------------------------


def test_org_scope_filter_none_returns_none() -> None:
    """No active org → no extra filter applied."""
    assert org_scope_filter(ScanJob.org_id, None) is None


def test_org_scope_filter_returns_or_expression() -> None:
    expr = org_scope_filter(ScanJob.org_id, uuid.uuid4())
    # It's an Or() — the str rendering contains both branches.
    rendered = str(expr.compile(compile_kwargs={"literal_binds": False}))
    assert "IS NULL" in rendered
    assert "scan_jobs.org_id =" in rendered


def test_apply_org_scope_is_passthrough_when_none() -> None:
    stmt = sa.select(ScanJob)
    out = apply_org_scope(stmt, ScanJob.org_id, None)
    # Same object — no clause added.
    assert str(stmt) == str(out)


# ---------------------------------------------------------------------------
# Integration tests against the in-memory SQLite session
# ---------------------------------------------------------------------------


async def _make_user(db, email: str) -> User:
    u = User(email=email, hashed_password=hash_password("pw"),
             is_active=True, plan=PlanTier.FREE)
    db.add(u)
    await db.flush()
    return u


async def _make_website(db, *, user_id, hostname: str,
                         org_id: uuid.UUID | None = None) -> Website:
    w = Website(
        user_id=user_id, url=f"https://{hostname}/",
        hostname=hostname, scheme="https",
        verification_status=VerificationStatus.VERIFIED,
        org_id=org_id,
    )
    db.add(w)
    await db.flush()
    return w


async def _make_scan(db, website_id, *, org_id=None,
                      status=ScanStatus.COMPLETED) -> ScanJob:
    job = ScanJob(
        website_id=website_id, status=status,
        requested_url="https://x/", org_id=org_id,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.flush()
    return job


@pytest.mark.asyncio
async def test_list_scan_jobs_no_active_org_sees_everything(db_engine) -> None:
    """Backwards compatibility — when no active_org_id is passed, EVERY
    row is visible regardless of which org it belongs to."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, "a@x.test")
        org_a = Org(slug="orga", name="A", plan_tier=PlanTier.FREE)
        org_b = Org(slug="orgb", name="B", plan_tier=PlanTier.FREE)
        db.add_all([org_a, org_b])
        await db.flush()
        w_legacy = await _make_website(db, user_id=u.id,
                                          hostname="legacy.test",
                                          org_id=None)
        w_a = await _make_website(db, user_id=u.id, hostname="a.test",
                                    org_id=org_a.id)
        w_b = await _make_website(db, user_id=u.id, hostname="b.test",
                                    org_id=org_b.id)
        await _make_scan(db, w_legacy.id, org_id=None)
        await _make_scan(db, w_a.id, org_id=org_a.id)
        await _make_scan(db, w_b.id, org_id=org_b.id)
        await db.commit()

    async with factory() as db:
        rows, total = await list_scan_jobs(db)
        assert total == 3


@pytest.mark.asyncio
async def test_list_scan_jobs_active_org_sees_own_and_legacy(db_engine) -> None:
    """With active_org_id=X — sees rows belonging to X *and* legacy NULL
    rows. Does NOT see rows belonging to a different org."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, "a@x.test")
        org_a = Org(slug="orga", name="A", plan_tier=PlanTier.FREE)
        org_b = Org(slug="orgb", name="B", plan_tier=PlanTier.FREE)
        db.add_all([org_a, org_b])
        await db.flush()
        org_a_id, org_b_id = org_a.id, org_b.id
        w_legacy = await _make_website(db, user_id=u.id,
                                          hostname="legacy.test")
        w_a = await _make_website(db, user_id=u.id, hostname="a.test",
                                    org_id=org_a_id)
        w_b = await _make_website(db, user_id=u.id, hostname="b.test",
                                    org_id=org_b_id)
        await _make_scan(db, w_legacy.id, org_id=None)
        await _make_scan(db, w_a.id, org_id=org_a_id)
        await _make_scan(db, w_b.id, org_id=org_b_id)
        await db.commit()

    async with factory() as db:
        rows, total = await list_scan_jobs(db, active_org_id=org_a_id)
        assert total == 2     # legacy + org A
        org_ids = {r.org_id for r in rows}
        # Includes NULL and org_a_id, never org_b_id
        assert org_b_id not in org_ids


@pytest.mark.asyncio
async def test_list_websites_active_org_excludes_other_org(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, "u@x.test")
        org_a = Org(slug="orga", name="A", plan_tier=PlanTier.FREE)
        org_b = Org(slug="orgb", name="B", plan_tier=PlanTier.FREE)
        db.add_all([org_a, org_b])
        await db.flush()
        org_a_id, org_b_id = org_a.id, org_b.id
        await _make_website(db, user_id=u.id, hostname="leg.test")
        await _make_website(db, user_id=u.id, hostname="a.test",
                              org_id=org_a_id)
        await _make_website(db, user_id=u.id, hostname="b.test",
                              org_id=org_b_id)
        await db.commit()

    async with factory() as db:
        rows, total = await list_websites(
            db, active_org_id=org_a_id,
        )
        hostnames = {w.hostname for w in rows}
        assert hostnames == {"leg.test", "a.test"}
        assert total == 2
