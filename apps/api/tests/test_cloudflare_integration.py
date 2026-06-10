"""Phase 4.2 — Cloudflare integration (service-level, Cloudflare HTTP mocked).

Uses the dev/ephemeral encryption key (no ENCRYPTION_KEYS in the test env); the
keyed paths are covered by the standalone validation. Guards the security core:
active-zone-only ownership, fail-closed without encryption, token-only-via-4.1,
no plaintext on the model/audit.
"""
from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import PlanTier, VerificationStatus
from apps.api.models.trusted_access import TrustedAccessProfile
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.services import cloudflare as cf
from apps.api.services.key_management import KeyManagementService

pytestmark = pytest.mark.anyio

TOKEN = "cf-ACCESS-PLAINTEXT-tok"
ACTIVE = [{"id": "z1", "name": "example.com", "status": "active",
           "account": {"id": "a1"}, "plan": {"name": "Pro"}}]
PENDING = [{"id": "zp", "name": "example.com", "status": "pending", "account": {"id": "a1"}}]
UNRELATED = [{"id": "zu", "name": "attacker.com", "status": "active", "account": {"id": "x"}}]


@pytest.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s


async def _site(db, email, host):
    u = User(email=email, hashed_password="x", is_active=True, plan=PlanTier.ENTERPRISE)
    db.add(u)
    await db.flush()
    w = Website(user_id=u.id, org_id=u.id, url=f"https://{host}", hostname=host,
                scheme="https", verification_status=VerificationStatus.UNVERIFIED)
    db.add(w)
    await db.flush()
    return u, w


def test_zone_match_active_only():
    assert cf.match_active_zone("www.example.com", ACTIVE) is not None
    assert cf.match_active_zone("example.com", ACTIVE) is not None
    assert cf.match_active_zone("example.com", PENDING) is None      # pending proves nothing
    assert cf.match_active_zone("victim.com", UNRELATED) is None     # unrelated never matches


def test_state_csrf():
    s = cf.sign_state(website_id=uuid.uuid4(), user_id=uuid.uuid4(), org_id=None)
    assert cf.verify_state(s)["purpose"] == "cf_oauth"
    with pytest.raises(cf.InvalidStateError):
        cf.verify_state("nope.nope.nope")


async def test_successful_connect(db_session, monkeypatch):
    async def fake_ex(code):
        return {"access_token": TOKEN, "refresh_token": "rf", "scope": "account:read zone:read"}
    async def fake_z(token):
        return ACTIVE
    monkeypatch.setattr(cf, "_exchange_code", fake_ex)
    monkeypatch.setattr(cf, "_fetch_zones", fake_z)
    u, w = await _site(db_session, "cf1@x.com", "www.example.com")
    res = await cf.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert res["matched"] and w.verification_status == VerificationStatus.VERIFIED
    conn = await cf.get_connection(db_session, w.id)
    assert conn.connection_status == "connected" and conn.zone_name == "example.com"
    sec = await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.resource_type == "cloudflare",
        EncryptedSecret.secret_type == "oauth_access_token"))
    assert sec is not None and TOKEN not in sec.ciphertext          # stored via 4.1, encrypted
    assert TOKEN not in repr(conn.__dict__)                          # never on the connection model
    ta = await db_session.scalar(sa.select(TrustedAccessProfile).where(
        TrustedAccessProfile.website_id == w.id))
    assert ta.access_method == "provider_oauth" and ta.access_status == "pending"
    rows = await db_session.scalars(sa.select(AdminAuditLog))
    assert TOKEN not in " ".join(repr(x.detail) for x in rows)       # never in audit


async def test_unrelated_zone_no_verify_no_token(db_session, monkeypatch):
    async def fake_ex(code):
        return {"access_token": TOKEN, "scope": "zone:read"}
    async def fake_z(token):
        return UNRELATED
    monkeypatch.setattr(cf, "_exchange_code", fake_ex)
    monkeypatch.setattr(cf, "_fetch_zones", fake_z)
    u, w = await _site(db_session, "cf2@x.com", "victim.com")
    res = await cf.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert res["matched"] is False and w.verification_status == VerificationStatus.UNVERIFIED
    assert await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.website_id == w.id)) is None                 # token discarded, never stored


async def test_fail_closed_without_encryption(db_session, monkeypatch):
    monkeypatch.setattr(cf, "get_key_management", lambda: KeyManagementService({}, None))
    async def fake_z(token):
        return ACTIVE
    monkeypatch.setattr(cf, "_fetch_zones", fake_z)
    u, w = await _site(db_session, "cf3@x.com", "example.com")
    with pytest.raises(cf.EncryptionNotConfiguredError):
        await cf.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.website_id == w.id)) is None
    assert w.verification_status == VerificationStatus.UNVERIFIED
