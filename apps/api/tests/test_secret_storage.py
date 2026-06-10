"""Phase 4.1 — secret storage + encryption at rest (service-level).

Uses the dev/ephemeral key (no ENCRYPTION_KEYS in the test env). The keyed,
rotation, and fail-closed paths are covered by the standalone validation; this
guards the core guarantees (encrypt, redact, reveal, revoke, isolation,
no-plaintext-in-audit) in CI.
"""
from __future__ import annotations

import sqlalchemy as sa
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.enums import PlanTier
from apps.api.models.user import User
from apps.api.services import secret_storage as ss

pytestmark = pytest.mark.anyio

SENTINEL = "tok-PLAINTEXT-xyz-789"
META_SECRET = "re_innermetadatasecret"


@pytest.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s


async def _org(db, email: str):
    u = User(email=email, hashed_password="x", is_active=True, plan=PlanTier.ENTERPRISE)
    db.add(u)
    await db.flush()
    return u.id


async def test_store_encrypts_and_reveal_roundtrips(db_session):
    org = await _org(db_session, "s1@x.com")
    secret = await ss.store_secret(
        db_session, resource_type="cloudflare", secret_type="oauth_access_token",
        plaintext=SENTINEL, org_id=org,
        metadata={"api_key": META_SECRET, "scopes": ["read"]})
    await db_session.flush()
    assert SENTINEL not in secret.ciphertext
    assert secret.secret_metadata["api_key"] == "<redacted>"   # redacted on store
    assert secret.secret_metadata["scopes"] == ["read"]
    pt = await ss.reveal_secret(db_session, secret, actor="system:test")
    assert pt == SENTINEL
    assert secret.access_count == 1 and secret.last_accessed_at is not None


async def test_revoke_wipes_and_blocks_reveal(db_session):
    org = await _org(db_session, "s2@x.com")
    secret = await ss.store_secret(
        db_session, resource_type="vercel", secret_type="api_key",
        plaintext=SENTINEL, org_id=org)
    await ss.revoke_secret(db_session, secret)
    assert secret.status == "revoked" and secret.ciphertext == ""
    with pytest.raises(ss.SecretRevokedError):
        await ss.reveal_secret(db_session, secret)


async def test_tenant_isolation(db_session):
    a = await _org(db_session, "s3a@x.com")
    b = await _org(db_session, "s3b@x.com")
    await ss.store_secret(db_session, resource_type="shopify",
                          secret_type="oauth_access_token", plaintext=SENTINEL, org_id=a)
    await db_session.flush()
    assert await ss.get_active_secret(db_session, resource_type="shopify",
                                      secret_type="oauth_access_token", org_id=b) is None
    assert await ss.get_active_secret(db_session, resource_type="shopify",
                                      secret_type="oauth_access_token", org_id=a) is not None


async def test_no_plaintext_in_audit(db_session):
    org = await _org(db_session, "s4@x.com")
    await ss.store_secret(db_session, resource_type="wix", secret_type="api_key",
                          plaintext=SENTINEL, org_id=org, metadata={"token": META_SECRET})
    await db_session.flush()
    rows = await db_session.scalars(
        sa.select(AdminAuditLog).where(AdminAuditLog.action == "secret.created"))
    blob = " ".join(repr(r.detail) for r in rows)
    assert SENTINEL not in blob and META_SECRET not in blob
