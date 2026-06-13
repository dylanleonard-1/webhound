"""Deterministic monitoring-schedule creation for onboarding.

Regression coverage for the bug where onboarding never reached `completed`
because the auto-monitoring ScanSchedule was missing: the dev-skip verification
path returned early WITHOUT creating it, and `activate_monitoring` only ENABLED
(never created) schedules — so completion fragilely depended on which path/timing
created the row.

The fix makes `verification.ensure_default_schedule` the single, idempotent
get-or-create seam, called synchronously wherever onboarding needs the schedule
(every verification path, including dev-skip, and monitoring activation). These
tests prove: deterministic creation, reuse, no duplicates, and that completion
does not depend on background-automation timing.
"""
from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.config import Settings
from apps.api.models.enums import VerificationMethod, VerificationStatus
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.website import Website
from apps.api.services import onboarding_readiness as ob
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _t(*_a, **_k) -> bool:
    return True


def _factory(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False)


async def _make_website(db_engine, user, *, verified: bool = False) -> uuid.UUID:
    """Create a Website row directly (no HTTP, no background task) so these are
    pure service-level tests with full control over schedule state."""
    async with _factory(db_engine)() as s:
        w = Website(
            url="https://sched-example.com",
            hostname="sched-example.com",
            scheme="https",
            user_id=user.id,
            verification_status=(
                VerificationStatus.VERIFIED if verified else VerificationStatus.UNVERIFIED),
        )
        s.add(w)
        await s.commit()
        await s.refresh(w)
        return w.id


async def _count_schedules(db_engine, website_id: uuid.UUID) -> int:
    async with _factory(db_engine)() as s:
        return len((await s.scalars(
            sa.select(ScanSchedule).where(ScanSchedule.website_id == website_id))).all())


# --- (2) missing ScanSchedule is created deterministically ------------------

async def test_ensure_creates_schedule_when_missing(db_engine, _test_user):
    wid = await _make_website(db_engine, _test_user, verified=True)
    assert await _count_schedules(db_engine, wid) == 0

    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        sched = await vs.ensure_default_schedule(s, w)
        await s.commit()
        assert sched is not None
        assert sched.is_enabled is True  # created ENABLED (auto-monitoring contract)

    assert await _count_schedules(db_engine, wid) == 1


async def test_activate_monitoring_creates_schedule_when_missing(db_engine, _test_user):
    """activate_monitoring is the point onboarding needs monitoring on — it must
    get-or-create the schedule, not assume verification already made it."""
    wid = await _make_website(db_engine, _test_user, verified=True)
    assert await _count_schedules(db_engine, wid) == 0

    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        # Stub readiness to READY so activation proceeds to the schedule step;
        # this isolates the schedule behaviour from the (separately tested) gate.
        async def _ready(_db, _w):
            return {
                "status": "ready", "checks": {}, "monitoring_allowed": True,
                "deep_scan_allowed": True, "baseline_allowed": True,
                "provider": "cloudflare", "verification": "verified",
                "trusted_access": "active", "validation": "ready",
                "provider_connected": "pass",
                "providers": {"detected": [], "connected": [], "missing": []},
                "evidence": [],
            }

        orig = ob.evaluate
        ob.evaluate = _ready  # type: ignore[assignment]
        try:
            await ob.activate_monitoring(s, w, user_id=_test_user.id)
        finally:
            ob.evaluate = orig  # type: ignore[assignment]
        await s.commit()

    # Exactly one, and it is enabled.
    assert await _count_schedules(db_engine, wid) == 1
    async with _factory(db_engine)() as s:
        sched = await s.scalar(
            sa.select(ScanSchedule).where(ScanSchedule.website_id == wid))
        assert sched.is_enabled is True


# --- (3) existing ScanSchedule is reused ------------------------------------

async def test_ensure_reuses_existing_schedule(db_engine, _test_user):
    wid = await _make_website(db_engine, _test_user, verified=True)
    # Seed one schedule first.
    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        first = await vs.ensure_default_schedule(s, w)
        first_id = first.id
        await s.commit()

    # Second call returns the SAME row, no new insert.
    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        second = await vs.ensure_default_schedule(s, w)
        await s.commit()
        assert second.id == first_id

    assert await _count_schedules(db_engine, wid) == 1


async def test_ensure_does_not_flip_disabled_schedule(db_engine, _test_user):
    """Reuse must respect a user who disabled monitoring — ensure never
    re-enables an existing schedule (enabling is activation's explicit job)."""
    wid = await _make_website(db_engine, _test_user, verified=True)
    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        sched = await vs.ensure_default_schedule(s, w)
        sched.is_enabled = False
        await s.commit()

    async with _factory(db_engine)() as s:
        w = await s.get(Website, wid)
        reused = await vs.ensure_default_schedule(s, w)
        await s.commit()
        assert reused.is_enabled is False  # left untouched


# --- (4) no duplicate schedules created -------------------------------------

async def test_repeated_ensure_creates_no_duplicates(db_engine, _test_user):
    wid = await _make_website(db_engine, _test_user, verified=True)
    # Many calls across many sessions (verification re-runs, activation, etc.).
    for _ in range(5):
        async with _factory(db_engine)() as s:
            w = await s.get(Website, wid)
            await vs.ensure_default_schedule(s, w)
            await s.commit()
    assert await _count_schedules(db_engine, wid) == 1


# --- (5) background-automation timing does not affect completion ------------

async def _verify_via_dns(client, monkeypatch, wid: str) -> None:
    monkeypatch.setattr(vs, "_check_dns", _t)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True


async def test_dev_skip_verification_creates_schedule(client, monkeypatch, db_engine):
    """The dev-skip verification path must create the schedule too — the original
    bug was that it returned early and left monitoring unable to activate."""
    # Force the dev-skip branch regardless of local .env.
    skip_settings = Settings(dev_skip_domain_verification=True)
    monkeypatch.setattr(vs, "get_settings", lambda: skip_settings)

    r = await client.post("/websites", json={"url": "https://example.com"})
    wid = r.json()["id"]
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True

    assert await _count_schedules(db_engine, uuid.UUID(wid)) == 1


async def test_completion_independent_of_background_timing(client, monkeypatch, db_engine):
    """Onboarding completes via the synchronous request path alone — it must NOT
    depend on the best-effort background automation task running first, and
    running automation first (which pauses at verification, creating no schedule)
    must not change the outcome or create duplicates.

    Forces the REAL-proof verification branch (dev-skip OFF) so the timing test
    doesn't alias with the dev-skip path covered above.
    """
    real_settings = Settings(dev_skip_domain_verification=False)
    monkeypatch.setattr(vs, "get_settings", lambda: real_settings)

    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile
    from apps.api.models.provider_connection import ProviderConnection
    from apps.api.services import access_validation as av

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    async def _meta(_db, _w):
        return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
                "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                     "challenge_provider": "unknown", "rendered_scripts_count": 12,
                                     "api_requests_count": 8, "evidence": []}}}, 10

    r = await client.post("/websites", json={"url": "https://example.com"})
    wid = r.json()["id"]

    # Background automation "runs first" via the same conductor and PAUSES at the
    # verification gate — it creates NO schedule at this point.
    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    auto = (await client.post(f"/websites/{wid}/onboarding/automate")).json()
    assert auto["status"] == "awaiting_verification"
    assert await _count_schedules(db_engine, uuid.UUID(wid)) == 0

    # Now the synchronous customer flow proceeds.
    await _verify_via_dns(client, monkeypatch, wid)
    assert (await client.post(f"/websites/{wid}/trusted-access/start")).status_code == 200
    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    assert (await client.post(f"/websites/{wid}/access-validation/run")).json()["status"] == "ready"
    async with _factory(db_engine)() as s:
        s.add(ProviderConnection(
            website_id=uuid.UUID(wid), provider="cloudflare", connection_status="connected"))
        await s.commit()

    body = (await client.post(f"/websites/{wid}/onboarding/wizard/sync")).json()
    assert body["overall_status"] == "completed"
    assert body["completion_percent"] == 100

    # Re-running automation to completion AFTER the fact must not create a duplicate.
    (await client.post(f"/websites/{wid}/onboarding/automate")).json()
    assert await _count_schedules(db_engine, uuid.UUID(wid)) == 1
