"""Phase 3.6 — onboarding readiness & activation (HTTP).

The full READY path is driven through the real Phase 3.1-3.5 endpoints
(verify -> discover -> trusted access -> validate), with network + latest-scan
metadata mocked. Classification detail is covered by the standalone validation.
"""
from __future__ import annotations

import uuid

import pytest

from apps.api.services import access_validation as av
from apps.api.services import onboarding_readiness as ob
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _t(*_a, **_k) -> bool:
    return True


async def _create(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _ready_meta() -> dict:
    return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
            "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                 "challenge_provider": "unknown",
                                 "rendered_scripts_count": 12, "api_requests_count": 8,
                                 "evidence": []}}}


async def _connect_provider(db_engine, wid: str, provider: str = "cloudflare") -> None:
    # Completion now requires the DETECTED provider to be CONNECTED (Phase 4.2).
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from apps.api.models.provider_connection import ProviderConnection
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        s.add(ProviderConnection(
            website_id=uuid.UUID(wid), provider=provider, connection_status="connected"))
        await s.commit()


async def _make_ready(client, monkeypatch, wid: str, db_engine) -> None:
    # verify ownership
    monkeypatch.setattr(vs, "_check_dns", _t)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True
    # provider discovery
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    assert (await client.post(f"/websites/{wid}/providers/discover")).status_code == 200
    # trusted access
    assert (await client.post(f"/websites/{wid}/trusted-access/start")).status_code == 200
    # access validation -> ready (drives trusted access to active)
    async def _meta(_db, _w):
        return _ready_meta(), 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    assert (await client.post(f"/websites/{wid}/access-validation/run")).json()["status"] == "ready"
    # Connect the DETECTED provider (Cloudflare) — completion gate.
    await _connect_provider(db_engine, wid, "cloudflare")


async def test_get_onboarding_not_ready_by_default(client):
    wid = await _create(client)
    body = (await client.get(f"/websites/{wid}/onboarding")).json()
    assert body["status"] == "not_ready"
    assert body["monitoring_allowed"] is False
    assert body["monitoring"] == "blocked"


async def test_activate_blocked_when_not_ready(client):
    wid = await _create(client)
    r = await client.post(f"/websites/{wid}/onboarding/activate-monitoring")
    assert r.status_code == 409
    # Real API contract: the app's errors.http_exception_handler wraps every
    # HTTPException as {"error": {"code", "message", "details"}}. A 409 maps to
    # code "conflict"; the endpoint's not_ready signal is carried in the message.
    body = r.json()
    assert body["error"]["code"] == "conflict"
    assert "not_ready" in body["error"]["message"]


async def test_full_ready_path_activates_monitoring(client, monkeypatch, db_engine):
    wid = await _create(client)
    await _make_ready(client, monkeypatch, wid, db_engine)
    body = (await client.get(f"/websites/{wid}/onboarding")).json()
    assert body["status"] == "ready"
    assert body["monitoring_allowed"] is True
    assert body["deep_scan_allowed"] is True

    r = await client.post(f"/websites/{wid}/onboarding/activate-monitoring")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ready"
    assert r.json()["monitoring"] == "active"


async def test_other_users_website_is_404(client):
    r = await client.get(f"/websites/{uuid.uuid4()}/onboarding")
    assert r.status_code == 404


async def test_activation_events_fire(client, monkeypatch, db_engine):
    wid = await _create(client)
    await _make_ready(client, monkeypatch, wid, db_engine)
    events: list[str] = []
    monkeypatch.setattr(ob, "emit_onboarding_event",
                        lambda event, website, **k: events.append(event))
    await client.post(f"/websites/{wid}/onboarding/activate-monitoring")
    assert ob.ONBOARDING_STARTED in events
    assert ob.ONBOARDING_READY in events
    assert ob.MONITORING_ACTIVATION_ALLOWED in events
    assert ob.DEEP_SCAN_ACTIVATION_ALLOWED in events
