# WebHound — apps/api/tests/test_orgs_and_delta.py
# Phase-4 multi-tenancy + scan-delta unit tests.

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

# DB-backed tests use the project's anyio fixture (asyncio backend, set in
# conftest.py). Pure-Python tests below don't need the marker but inherit
# it harmlessly via the module-level pytestmark.
pytestmark = pytest.mark.anyio

from apps.api.models.enums import DriftSeverity, OrgRole, PlanTier
from apps.api.models.org import Org, OrgMembership
from apps.api.models.user import User
from apps.api.security import hash_password
from apps.api.services.orgs import (
    OrgServiceError,
    add_membership,
    check_ownership,
    create_org,
    has_org_role,
    list_user_orgs,
    normalize_slug,
)
from apps.api.services.scan_delta import (
    ComputedDelta,
    ScanFingerprint,
    compute_delta,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_user(db, email: str) -> User:
    u = User(email=email, hashed_password=hash_password("pw"),
             is_active=True, plan=PlanTier.FREE)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


# ---------------------------------------------------------------------------
# Slug normalisation
# ---------------------------------------------------------------------------


def test_normalize_slug_lowercases_and_hyphenates() -> None:
    assert normalize_slug("Acme Corp") == "acme-corp"
    assert normalize_slug("  Hello_World!  ") == "hello-world"


def test_normalize_slug_rejects_empty_or_bad() -> None:
    with pytest.raises(OrgServiceError):
        normalize_slug("")
    with pytest.raises(OrgServiceError):
        normalize_slug("-")
    with pytest.raises(OrgServiceError):
        normalize_slug("a" * 64)   # too long


# ---------------------------------------------------------------------------
# Org service — DB-backed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_org_makes_founder_owner(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        owner = await _make_user(db, "owner@acme.test")
        org = await create_org(
            db, name="Acme", slug="acme",
            owner_user_id=owner.id, billing_email="b@acme.test",
        )
        await db.commit()
        # Founder should appear as an accepted OWNER member.
        async with factory() as db2:
            from apps.api.services.orgs import get_membership
            m = await get_membership(db2, org_id=org.id, user_id=owner.id)
            assert m is not None
            assert m.role == OrgRole.OWNER
            assert m.accepted_at is not None


@pytest.mark.asyncio
async def test_create_org_rejects_duplicate_slug(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        owner = await _make_user(db, "a@x.test")
        await create_org(db, name="Acme", slug="acme",
                          owner_user_id=owner.id)
        await db.commit()
    async with factory() as db:
        owner2 = await _make_user(db, "b@x.test")
        with pytest.raises(OrgServiceError):
            await create_org(db, name="Acme Two", slug="acme",
                              owner_user_id=owner2.id)


@pytest.mark.asyncio
async def test_add_membership_idempotency(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        owner = await _make_user(db, "o@x.test")
        viewer = await _make_user(db, "v@x.test")
        org = await create_org(db, name="X", slug="x",
                                owner_user_id=owner.id)
        await add_membership(
            db, org_id=org.id, user_id=viewer.id,
            role=OrgRole.VIEWER, auto_accept=True,
        )
        await db.commit()
        # Re-adding should raise rather than silently changing role.
        with pytest.raises(OrgServiceError):
            await add_membership(
                db, org_id=org.id, user_id=viewer.id,
                role=OrgRole.ADMIN, auto_accept=True,
            )


@pytest.mark.asyncio
async def test_list_user_orgs_returns_only_accepted(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        owner = await _make_user(db, "o@x.test")
        org_a = await create_org(db, name="A", slug="a",
                                   owner_user_id=owner.id)
        org_b = await create_org(db, name="B", slug="b",
                                   owner_user_id=owner.id)
        await db.commit()
        async with factory() as db2:
            results = await list_user_orgs(db2, owner.id)
        slugs = sorted(o.slug for o, _ in results)
        assert slugs == ["a", "b"]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_has_org_role_owner_satisfies_everything() -> None:
    assert has_org_role(OrgRole.OWNER, OrgRole.VIEWER)
    assert has_org_role(OrgRole.OWNER, OrgRole.ADMIN)
    assert has_org_role(OrgRole.OWNER, OrgRole.OWNER)


def test_has_org_role_viewer_does_not_satisfy_higher() -> None:
    assert has_org_role(OrgRole.VIEWER, OrgRole.VIEWER)
    assert not has_org_role(OrgRole.VIEWER, OrgRole.ANALYST)
    assert not has_org_role(OrgRole.VIEWER, OrgRole.ADMIN)


def test_has_org_role_none_fails_everything() -> None:
    assert not has_org_role(None, OrgRole.VIEWER)


@pytest.mark.asyncio
async def test_check_ownership_permissive_when_org_id_none(db_engine) -> None:
    """During the scaffold phase, an entity with no org_id is treated as
    single-tenant legacy — ownership check passes. (The cutover migration
    removes this branch.)"""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        user = await _make_user(db, "x@y.test")
        ok = await check_ownership(
            db, user_id=user.id, org_id=None,
            minimum_role=OrgRole.ADMIN,
        )
        assert ok is True


@pytest.mark.asyncio
async def test_check_ownership_blocks_non_member(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        owner = await _make_user(db, "o@x.test")
        intruder = await _make_user(db, "i@x.test")
        org = await create_org(db, name="X", slug="x",
                                owner_user_id=owner.id)
        await db.commit()
        async with factory() as db2:
            assert await check_ownership(
                db2, user_id=intruder.id, org_id=org.id,
                minimum_role=OrgRole.VIEWER,
            ) is False
            assert await check_ownership(
                db2, user_id=owner.id, org_id=org.id,
                minimum_role=OrgRole.ADMIN,
            ) is True


# ---------------------------------------------------------------------------
# Scan delta — pure-function diff
# ---------------------------------------------------------------------------


def _fp(**overrides) -> ScanFingerprint:
    base = dict(
        scan_job_id=uuid.uuid4(),
        website_id=uuid.uuid4(),
        org_id=None,
        risk_score=50,
        external_domains=set(),
        technologies=set(),
        security_headers={},
        tls_summary={},
        forms=[],
        apis=[],
        finding_severity_counts={},
    )
    base.update(overrides)
    return ScanFingerprint(**base)


def test_compute_delta_initial_scan_has_no_drift() -> None:
    fp = _fp()
    delta = compute_delta(fp, None)
    assert delta.drift_severity == DriftSeverity.NONE
    assert delta.previous_scan_job_id is None
    assert "Initial scan" in (delta.drift_summary or "")


def test_compute_delta_clean_scan_no_changes_is_NONE() -> None:
    wid = uuid.uuid4()
    a = _fp(website_id=wid, external_domains={"cdn.example.com"})
    b = _fp(website_id=wid, external_domains={"cdn.example.com"})
    delta = compute_delta(b, a)
    assert delta.drift_severity == DriftSeverity.NONE


def test_compute_delta_new_domains_only_is_LOW_MEDIUM() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid, external_domains={"cdn.example.com"})
    cur = _fp(website_id=wid, external_domains={
        "cdn.example.com", "new1.example.com",
    })
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.LOW
    assert delta.new_domains == [{"domain": "new1.example.com"}]


def test_compute_delta_many_new_domains_is_HIGH() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid, external_domains=set())
    cur = _fp(website_id=wid, external_domains={
        f"x{i}.example.com" for i in range(6)
    })
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.HIGH


def test_compute_delta_tls_change_is_CRITICAL() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid, tls_summary={"min_tls_version": "TLSv1.2"})
    cur = _fp(website_id=wid, tls_summary={"min_tls_version": "TLSv1.0"})
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.CRITICAL
    assert "min_tls_version" in delta.changed_tls


def test_compute_delta_removed_high_signal_header_is_CRITICAL() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid, security_headers={
        "Content-Security-Policy": "default-src 'self'",
    })
    cur = _fp(website_id=wid, security_headers={})
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.CRITICAL


def test_compute_delta_admin_form_appearing_is_HIGH() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid)
    cur = _fp(website_id=wid, forms=["https://target/admin/login"])
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.HIGH


def test_compute_delta_risk_worsening_20_is_CRITICAL() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid, risk_score=30)
    cur = _fp(website_id=wid, risk_score=60)
    delta = compute_delta(cur, prev)
    assert delta.drift_severity == DriftSeverity.CRITICAL
    assert delta.risk_score_delta == 30


def test_compute_delta_summary_is_non_empty_when_changes() -> None:
    wid = uuid.uuid4()
    prev = _fp(website_id=wid)
    cur = _fp(website_id=wid, external_domains={"new.example.com"})
    delta = compute_delta(cur, prev)
    assert delta.drift_summary
    assert "no meaningful" not in (delta.drift_summary or "").lower()
