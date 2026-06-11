"""Phase 3.7 — onboarding wizard (HTTP).

Drives the real Phase 3.1-3.6 endpoints (verify -> discover -> trusted access ->
validate) to advance the wizard. Note: verification auto-creates an enabled
monitoring schedule (3.2), so the monitoring step is active post-verify.
Classification detail is covered by the standalone validation.
"""
from __future__ import annotations

import uuid

import pytest

from apps.api.services import access_validation as av
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _t(*_a, **_k) -> bool:
    return True


async def _create(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _verify_and_discover(client, monkeypatch, wid: str) -> None:
    monkeypatch.setattr(vs, "_check_dns", _t)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    assert (await client.post(f"/websites/{wid}/providers/discover")).status_code == 200


async def _connect_provider(db_engine, wid: str, provider: str = "cloudflare") -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from apps.api.models.provider_connection import ProviderConnection
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        s.add(ProviderConnection(
            website_id=uuid.UUID(wid), provider=provider, connection_status="connected"))
        await s.commit()


async def _make_ready(client, monkeypatch, wid: str, db_engine) -> None:
    await _verify_and_discover(client, monkeypatch, wid)
    assert (await client.post(f"/websites/{wid}/trusted-access/start")).status_code == 200

    async def _meta(_db, _w):
        return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
                "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                     "challenge_provider": "unknown",
                                     "rendered_scripts_count": 12, "api_requests_count": 8,
                                     "evidence": []}}}, 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    assert (await client.post(f"/websites/{wid}/access-validation/run")).json()["status"] == "ready"
    # Completion now requires the DETECTED provider (Cloudflare) to be CONNECTED.
    await _connect_provider(db_engine, wid, "cloudflare")


async def test_wizard_not_started_when_fresh(client):
    wid = await _create(client)
    body = (await client.get(f"/websites/{wid}/onboarding/wizard")).json()
    assert body["overall_status"] == "not_started"
    assert len(body["steps"]) == 6
    assert body["completion_percent"] == 0


async def test_wizard_sync_fresh(client):
    wid = await _create(client)
    r = await client.post(f"/websites/{wid}/onboarding/wizard/sync")
    assert r.status_code == 200
    assert r.json()["overall_status"] == "not_started"
    assert r.json()["current_step"] == 1


async def test_wizard_completes_after_full_flow(client, monkeypatch, db_engine):
    wid = await _create(client)
    await _make_ready(client, monkeypatch, wid, db_engine)
    # Monitoring is already active via the auto-schedule created on verification.
    body = (await client.post(f"/websites/{wid}/onboarding/wizard/sync")).json()
    assert body["overall_status"] == "completed"
    assert body["completion_percent"] == 100
    assert body["current_step"] == 6


async def test_wizard_resume_does_not_restart(client, monkeypatch):
    wid = await _create(client)
    # verify + discover only — steps 3/4/5 still pending (monitoring active via verify).
    await _verify_and_discover(client, monkeypatch, wid)
    r1 = await client.post(f"/websites/{wid}/onboarding/wizard/sync")
    assert r1.json()["overall_status"] == "in_progress"
    assert r1.json()["current_step"] == 3
    # Resume: syncing again stays at the same step — never restarts.
    r2 = await client.post(f"/websites/{wid}/onboarding/wizard/sync")
    assert r2.json()["current_step"] == 3


async def test_other_users_website_is_404(client):
    r = await client.get(f"/websites/{uuid.uuid4()}/onboarding/wizard")
    assert r.status_code == 404
