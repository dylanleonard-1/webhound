"""Phase 4.3 — Vercel integration (service-level, Vercel HTTP mocked).

Reuses the shared provider-OAuth base + the generic ProviderConnection (no new
model/migration). Guards the security core: EXACT verified-domain match only,
fail-closed without encryption, token-only-via-4.1, no plaintext on model/audit,
and the owned-domain bypass never applied to customer domains (§7/§12).
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
from apps.api.services import provider_oauth
from apps.api.services import vercel as v
from apps.api.services.key_management import KeyManagementService
from apps.api.services.trusted_access import is_owned_domain

pytestmark = pytest.mark.anyio

TOKEN = "v-ACCESS-PLAINTEXT-tok"
VERIFIED = [{"id": "p1", "name": "Site", "accountId": "t1", "framework": "nextjs",
             "domains": [{"name": "example.com", "verified": True},
                         {"name": "www.example.com", "verified": True}]}]
UNVERIFIED = [{"id": "p2", "name": "Pending", "accountId": "t1",
               "domains": [{"name": "example.com", "verified": False}]}]
APEX_ONLY = [{"id": "p4", "name": "Apex", "accountId": "t1",
              "domains": [{"name": "example.com", "verified": True}]}]


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


def test_match_exact_verified_only():
    assert v.match_verified_domain("www.example.com", VERIFIED)[0] is not None
    assert v.match_verified_domain("example.com", VERIFIED)[0] is not None
    assert v.match_verified_domain("example.com", UNVERIFIED)[0] is None       # unverified proves nothing
    assert v.match_verified_domain("www.example.com", APEX_ONLY)[0] is None    # no subdomain inheritance


def test_state_csrf_and_provider_binding():
    s = v.sign_state(website_id=uuid.uuid4(), user_id=uuid.uuid4(), org_id=None)
    assert v.verify_state(s)["purpose"] == "vercel_oauth"
    with pytest.raises(provider_oauth.InvalidStateError):
        v.verify_state("nope.nope.nope")
    cf_state = provider_oauth.sign_state("cloudflare", website_id=uuid.uuid4(), user_id=None, org_id=None)
    with pytest.raises(provider_oauth.InvalidStateError):
        v.verify_state(cf_state)  # a cloudflare state must not validate as vercel


async def test_successful_connect(db_session, monkeypatch):
    async def fake_ex(code):
        return {"access_token": TOKEN, "refresh_token": "rf", "team_id": "t1"}
    async def fake_p(token, team):
        return VERIFIED
    monkeypatch.setattr(v, "_exchange_code", fake_ex)
    monkeypatch.setattr(v, "_fetch_projects", fake_p)
    # Auto-apply of the scanner bypass rule is exercised in test_vercel_scanner_access;
    # stub it here (no network) so this test isolates the connect/verify/token path and
    # trusted access stays pending (the scanner flow is what promotes it to active).
    from apps.api.services import vercel_scanner_access as _vsa
    async def fake_apply(db, **kw):
        return {"applied": False, "status": "pending_manual_setup"}
    monkeypatch.setattr(_vsa, "apply_ip_scanner_access", fake_apply)
    u, w = await _site(db_session, "v1@x.com", "www.example.com")
    res = await v.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert res["matched"] and w.verification_status == VerificationStatus.VERIFIED
    conn = await v.get_connection(db_session, w.id)
    assert conn.connection_status == "connected" and conn.zone_name == "www.example.com"
    sec = await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.resource_type == "vercel", EncryptedSecret.secret_type == "oauth_access_token"))
    assert sec is not None and TOKEN not in sec.ciphertext
    assert TOKEN not in repr(conn.__dict__)
    ta = await db_session.scalar(sa.select(TrustedAccessProfile).where(
        TrustedAccessProfile.website_id == w.id))
    assert ta.provider == "vercel" and ta.access_method == "provider_oauth" and ta.access_status == "pending"
    # owned-domain bypass never applied to a customer domain
    assert is_owned_domain("www.example.com") is False and ta.access_method != "internal_owned_domain"
    rows = await db_session.scalars(sa.select(AdminAuditLog))
    assert TOKEN not in " ".join(repr(x.detail) for x in rows)


async def test_unverified_domain_no_verify_no_token(db_session, monkeypatch):
    async def fake_ex(code):
        return {"access_token": TOKEN, "team_id": "t1"}
    async def fake_p(token, team):
        return UNVERIFIED
    monkeypatch.setattr(v, "_exchange_code", fake_ex)
    monkeypatch.setattr(v, "_fetch_projects", fake_p)
    u, w = await _site(db_session, "v2@x.com", "example.com")
    res = await v.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert res["matched"] is False and w.verification_status == VerificationStatus.UNVERIFIED
    assert await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.website_id == w.id)) is None


async def test_fail_closed_without_encryption(db_session, monkeypatch):
    monkeypatch.setattr(v, "get_key_management", lambda: KeyManagementService({}, None))
    async def fake_p(token, team):
        return VERIFIED
    monkeypatch.setattr(v, "_fetch_projects", fake_p)
    u, w = await _site(db_session, "v3@x.com", "example.com")
    with pytest.raises(provider_oauth.EncryptionNotConfiguredError):
        await v.complete_connection(db_session, website=w, code="c", user_id=u.id, org_id=u.id)
    await db_session.flush()
    assert await db_session.scalar(sa.select(EncryptedSecret).where(
        EncryptedSecret.website_id == w.id)) is None
    assert w.verification_status == VerificationStatus.UNVERIFIED
