# WebHound — apps/api/tests/test_suppressions.py
# Phase-5F suppression tests.

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.enums import PlanTier
from apps.api.models.suppression import SuppressionScope, Suppression
from apps.api.models.user import User
from apps.api.security import hash_password
from apps.api.services.suppressions import (
    SuppressionError,
    create_suppression,
    deactivate_suppression,
    is_finding_suppressed,
    list_suppressions,
)

pytestmark = pytest.mark.anyio


async def _user(db) -> User:
    u = User(email=f"u-{uuid.uuid4()}@x", hashed_password=hash_password("x"),
             is_active=True, plan=PlanTier.FREE)
    db.add(u)
    await db.flush()
    return u


# ---------------------------------------------------------------------------
# create_suppression
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_basic(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        s = await create_suppression(
            db, org_id=None, scope=SuppressionScope.DOMAIN,
            pattern="cdn.example.com", reason="known benign CDN",
            creator_email=u.email, creator_user_id=u.id,
        )
        await db.commit()
        assert s.id is not None
        assert s.is_live is True


@pytest.mark.asyncio
async def test_create_rejects_empty_pattern(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with pytest.raises(SuppressionError):
            await create_suppression(
                db, org_id=None, scope=SuppressionScope.DOMAIN,
                pattern="", reason="x",
            )


@pytest.mark.asyncio
async def test_create_rejects_empty_reason(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with pytest.raises(SuppressionError):
            await create_suppression(
                db, org_id=None, scope=SuppressionScope.DOMAIN,
                pattern="x.com", reason="",
            )


@pytest.mark.asyncio
async def test_expires_in_past_rejected(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with pytest.raises(SuppressionError):
            await create_suppression(
                db, org_id=None, scope=SuppressionScope.DOMAIN,
                pattern="x.com", reason="r",
                expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            )


# ---------------------------------------------------------------------------
# deactivate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deactivate_flips_is_active(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        s = await create_suppression(
            db, org_id=None, scope=SuppressionScope.DOMAIN,
            pattern="x.com", reason="r",
        )
        await db.commit()
        sid = s.id
    async with factory() as db:
        out = await deactivate_suppression(db, sid)
        assert out is not None
        assert out.is_active is False


# ---------------------------------------------------------------------------
# Matcher — domain
# ---------------------------------------------------------------------------


def _stub_supp(*, scope, pattern, engine=None, active=True,
                expires_at=None) -> Suppression:
    s = Suppression(
        id=uuid.uuid4(), scope=scope, pattern=pattern,
        scanner_engine=engine, reason="x",
        is_active=active, expires_at=expires_at,
    )
    return s


def test_matcher_domain_exact() -> None:
    s = _stub_supp(scope=SuppressionScope.DOMAIN, pattern="cdn.example.com")
    finding = {
        "title": "Suspicious host",
        "scanner_engine": "threat_intel",
        "evidence_location": "https://cdn.example.com/x",
    }
    assert is_finding_suppressed(finding, [s]) is s


def test_matcher_domain_wildcard() -> None:
    s = _stub_supp(scope=SuppressionScope.DOMAIN,
                   pattern="*.example.com")
    finding = {
        "title": "Suspicious host",
        "scanner_engine": "threat_intel",
        "evidence_location": "https://cdn.example.com/x",
    }
    assert is_finding_suppressed(finding, [s]) is s


def test_matcher_domain_no_match() -> None:
    s = _stub_supp(scope=SuppressionScope.DOMAIN,
                   pattern="cdn.example.com")
    finding = {
        "title": "Suspicious host",
        "scanner_engine": "threat_intel",
        "evidence_location": "https://other.com/x",
    }
    assert is_finding_suppressed(finding, [s]) is None


def test_matcher_finding_title_engine_scoped() -> None:
    s = _stub_supp(scope=SuppressionScope.FINDING_TITLE,
                   pattern="Missing CSP", engine="cookies")
    # Wrong engine — should NOT match.
    finding = {
        "title": "Missing CSP header",
        "scanner_engine": "security_headers",
    }
    assert is_finding_suppressed(finding, [s]) is None
    # Right engine — match.
    finding["scanner_engine"] = "cookies"
    assert is_finding_suppressed(finding, [s]) is s


def test_matcher_vendor() -> None:
    s = _stub_supp(scope=SuppressionScope.VENDOR, pattern="example.com")
    finding = {
        "title": "x",
        "metadata": {"registrable_domain": "example.com",
                      "host": "cdn.example.com"},
    }
    assert is_finding_suppressed(finding, [s]) is s


def test_matcher_inactive_suppression_ignored() -> None:
    s = _stub_supp(scope=SuppressionScope.DOMAIN,
                   pattern="cdn.example.com", active=False)
    finding = {
        "title": "x", "scanner_engine": "threat_intel",
        "evidence_location": "https://cdn.example.com/x",
    }
    assert is_finding_suppressed(finding, [s]) is None


def test_matcher_expired_suppression_ignored() -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    s = _stub_supp(scope=SuppressionScope.DOMAIN,
                   pattern="cdn.example.com", expires_at=past)
    finding = {
        "title": "x", "scanner_engine": "threat_intel",
        "evidence_location": "https://cdn.example.com/x",
    }
    assert is_finding_suppressed(finding, [s]) is None


def test_matcher_site_pattern() -> None:
    site_id = uuid.uuid4()
    s = _stub_supp(scope=SuppressionScope.SITE, pattern=str(site_id))
    finding = {"title": "x",
                "metadata": {"website_id": str(site_id)}}
    assert is_finding_suppressed(finding, [s]) is s


# ---------------------------------------------------------------------------
# list_suppressions org scoping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_org_scope_includes_null_org(db_engine) -> None:
    """Platform-wide (org_id=NULL) suppressions are visible to
    every tenant — that's the canonical 'managed by support' path."""
    from apps.api.models.org import Org

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        org = Org(slug="acme", name="Acme", plan_tier=PlanTier.FREE)
        db.add(org)
        await db.flush()
        await create_suppression(
            db, org_id=None,
            scope=SuppressionScope.DOMAIN,
            pattern="platform.example.com", reason="platform",
        )
        await create_suppression(
            db, org_id=org.id,
            scope=SuppressionScope.DOMAIN,
            pattern="tenant.example.com", reason="tenant",
        )
        await db.commit()
        rows = await list_suppressions(db, org_id=org.id)
        patterns = [s.pattern for s in rows]
        assert "platform.example.com" in patterns
        assert "tenant.example.com" in patterns
