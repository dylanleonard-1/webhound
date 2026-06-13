"""Phase 3.10 — onboarding automation (HTTP).

Exercises the automation conductor end-to-end through the real endpoint:
auto-discovery + pause at the verification gate, then a full run to completion.
Orchestration detail (resume, not_ready, audit) is covered by the standalone.
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


def _mock_discover(monkeypatch) -> None:
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)


async def _connect_provider(db_engine, wid: str, provider: str = "cloudflare") -> None:
    """Onboarding completion now requires every DETECTED provider to be CONNECTED
    (Phase 4.2). _mock_discover detects Cloudflare, so the flow must connect it."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from apps.api.models.provider_connection import ProviderConnection
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        s.add(ProviderConnection(
            website_id=uuid.UUID(wid), provider=provider, connection_status="connected"))
        await s.commit()


async def test_automate_fresh_pauses_at_verification(client, monkeypatch):
    _mock_discover(monkeypatch)
    wid = await _create(client)
    body = (await client.post(f"/websites/{wid}/onboarding/automate")).json()
    assert body["current_stage"] == "verification"
    assert body["status"] == "awaiting_verification"
    assert "provider_discovery" in body["completed_stages"]
    assert body["provider"]  # provider auto-detected
    assert body["next_action"]


async def test_automate_full_flow_completes(client, monkeypatch, db_engine):
    wid = await _create(client)
    # Verify ownership first so the automation clears the verification gate.
    monkeypatch.setattr(vs, "_check_dns", _t)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True
    _mock_discover(monkeypatch)

    async def _meta(_db, _w):
        return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
                "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                     "challenge_provider": "unknown", "rendered_scripts_count": 9,
                                     "api_requests_count": 4, "evidence": []}}}, 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    # Connect the DETECTED provider (Cloudflare) — completion now requires it.
    # Without this the flow correctly stays NOT_READY; we satisfy the real gate
    # rather than bypass it.
    await _connect_provider(db_engine, wid, "cloudflare")
    body = (await client.post(f"/websites/{wid}/onboarding/automate")).json()
    assert body["status"] == "completed"
    assert "verification" in body["completed_stages"]
    assert "trusted_access" in body["completed_stages"]
    assert "validation" in body["completed_stages"]
    assert "monitoring" in body["completed_stages"]


async def test_automate_other_users_website_is_404(client):
    r = await client.post(f"/websites/{uuid.uuid4()}/onboarding/automate")
    assert r.status_code == 404
