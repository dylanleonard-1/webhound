"""Phase 3.2 — ownership verification flow.

HTTP-level via the `client` fixture; the gate + cross-account conflict guard are
exercised against a direct DB session. Network verification checks (DNS/file/
meta) are monkeypatched so the suite stays hermetic.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.config import Settings
from apps.api.models.enums import (
    PlanTier,
    ScanProfile,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website
from apps.api.schemas.scan_jobs import ScanJobCreate
from apps.api.security import hash_password
from apps.api.services import scan_jobs as sj
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _create_website(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _always_true(*_a, **_k) -> bool:
    return True


# --- HTTP: the three fallback methods all reach VERIFIED -------------------

@pytest.mark.parametrize("method,check_fn", [
    ("dns_txt", "_check_dns"),
    ("html_file", "_check_file"),
    ("meta_tag", "_check_meta"),
])
async def test_verification_methods_succeed(client, monkeypatch, method, check_fn):
    monkeypatch.setattr(vs, check_fn, _always_true)
    wid = await _create_website(client)
    r = await client.post(f"/websites/{wid}/verify/initiate?method={method}")
    assert r.status_code == 200, r.text
    r2 = await client.post(f"/websites/{wid}/verify/check")
    assert r2.status_code == 200 and r2.json()["verified"] is True


async def test_retry_is_rechecking_with_same_token(client, monkeypatch):
    # "Retry" = re-calling check; the token is reused across polls.
    calls = {"n": 0}

    async def _flaky(*_a, **_k):
        calls["n"] += 1
        return calls["n"] >= 2

    monkeypatch.setattr(vs, "_check_dns", _flaky)
    wid = await _create_website(client)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    # Disable the dev bypass so the real (flaky) DNS check governs the result —
    # otherwise DEV_SKIP_DOMAIN_VERIFICATION short-circuits both polls to verified.
    with patch("apps.api.services.verification.get_settings",
               return_value=Settings(dev_skip_domain_verification=False)):
        assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is False
        assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True


async def test_get_verify_recommends_method(client):
    wid = await _create_website(client)
    body = (await client.get(f"/websites/{wid}/verify")).json()
    assert body["recommended_method"] == "dns_txt"  # no ProviderProfile → default
    assert set(body["fallback_methods"]) == {"meta_tag", "html_file"}


async def test_revoke_sets_revoked(client, monkeypatch):
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    wid = await _create_website(client)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    await client.post(f"/websites/{wid}/verify/check")
    r = await client.post(f"/websites/{wid}/verify/revoke")
    assert r.status_code == 200 and r.json()["verification_status"] == "revoked"


async def test_verification_events_fire(client, monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(
        vs, "emit_verification_event",
        lambda event, website, **k: events.append(event),
    )
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    wid = await _create_website(client)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    await client.post(f"/websites/{wid}/verify/check")
    await client.post(f"/websites/{wid}/verify/revoke")
    assert vs.VERIFICATION_STARTED in events
    assert vs.VERIFICATION_COMPLETED in events
    assert vs.VERIFICATION_REVOKED in events


async def test_duplicate_exact_url_conflicts(client):
    await _create_website(client, "https://dup.example.com")
    r = await client.post("/websites", json={"url": "https://dup.example.com"})
    assert r.status_code == 409


async def test_recommend_uses_provider_profile_cms():
    assert vs.recommend_verification(None)["recommended_method"] == "dns_txt"

    class _PP:
        cms = "Squarespace"

    rec = vs.recommend_verification(_PP())
    assert rec["recommended_method"] == "meta_tag"
    assert "dns_txt" in rec["fallback_methods"]


# --- Service-level: gate + cross-account ownership conflict ----------------

@pytest.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s


async def _mk_user(db, email: str) -> User:
    u = User(email=email, hashed_password=hash_password("x12345678"),
             is_active=True, plan=PlanTier.ENTERPRISE)
    db.add(u)
    await db.flush()
    return u


async def _mk_website(db, user, url, hostname, status=VerificationStatus.UNVERIFIED) -> Website:
    w = Website(user_id=user.id, url=url, hostname=hostname, scheme="https",
                verification_status=status)
    db.add(w)
    await db.flush()
    return w


async def test_gate_blocks_unverified_revoked_allows_admin_verified(db_session):
    user = await _mk_user(db_session, "gate@example.com")
    w = await _mk_website(db_session, user, "https://g.example.com/", "g.example.com")
    data = ScanJobCreate(website_id=w.id, profile=ScanProfile.STANDARD)
    with patch("apps.api.services.scan_jobs.get_settings",
               return_value=Settings(dev_allow_unverified_scans=False)):
        # unverified + non-admin → blocked
        with pytest.raises(sj.WebsiteNotVerifiedError):
            await sj.create_scan_job(db_session, data, user_id=user.id, is_admin=False)
        # admin/internal path → allowed (unchanged)
        assert await sj.create_scan_job(db_session, data, user_id=None, is_admin=True)
        # verified → allowed
        w.verification_status = VerificationStatus.VERIFIED
        await db_session.flush()
        assert await sj.create_scan_job(db_session, data, user_id=user.id, is_admin=False)
        # revoked → blocked
        w.verification_status = VerificationStatus.REVOKED
        await db_session.flush()
        with pytest.raises(sj.WebsiteNotVerifiedError):
            await sj.create_scan_job(db_session, data, user_id=user.id, is_admin=False)


async def test_cross_account_variant_ownership_conflict(db_session, monkeypatch):
    # User A verified the apex; User B must NOT be able to verify the www variant.
    a = await _mk_user(db_session, "a@example.com")
    await _mk_website(db_session, a, "https://conflict.com/", "conflict.com",
                      VerificationStatus.VERIFIED)
    b = await _mk_user(db_session, "b@example.com")
    wb = await _mk_website(db_session, b, "https://www.conflict.com/", "www.conflict.com")
    dv = DomainVerification(website_id=wb.id, method=VerificationMethod.DNS_TXT,
                            token="tok", status=VerificationStatus.PENDING)
    db_session.add(dv)
    await db_session.flush()
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    with patch("apps.api.services.verification.get_settings",
               return_value=Settings(dev_skip_domain_verification=False)):
        with pytest.raises(vs.OwnershipConflictError):
            await vs.check_verification(db_session, wb, dv)
    assert wb.verification_status != VerificationStatus.VERIFIED


async def test_no_conflict_for_unique_hostname(db_session, monkeypatch):
    a = await _mk_user(db_session, "solo@example.com")
    wa = await _mk_website(db_session, a, "https://solo.example/", "solo.example")
    dv = DomainVerification(website_id=wa.id, method=VerificationMethod.DNS_TXT,
                            token="tok2", status=VerificationStatus.PENDING)
    db_session.add(dv)
    await db_session.flush()
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    with patch("apps.api.services.verification.get_settings",
               return_value=Settings(dev_skip_domain_verification=False)):
        assert await vs.check_verification(db_session, wa, dv) is True
    assert wa.verification_status == VerificationStatus.VERIFIED
