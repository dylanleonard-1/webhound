"""Phase 3.4 — trusted scanner access foundation (HTTP).

State is set up through the client's OWN endpoints (verify + provider discovery,
network mocked) so everything shares one session/DB. The deeper service logic
(preconditions, tenant isolation, owned-domain, no-secrets) is covered by the
standalone service validation.
"""
from __future__ import annotations

import uuid

import pytest

from apps.api.services import trusted_access as ta
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _always_true(*_a, **_k) -> bool:
    return True


async def _create_website(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _verify(client, monkeypatch, wid: str) -> None:
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    r = await client.post(f"/websites/{wid}/verify/check")
    assert r.json()["verified"] is True


async def _discover_cloudflare(client, monkeypatch, wid: str) -> None:
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    r = await client.post(f"/websites/{wid}/providers/discover")
    assert r.status_code == 200, r.text


async def test_start_blocked_when_unverified(client):
    wid = await _create_website(client)
    r = await client.post(f"/websites/{wid}/trusted-access/start")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "ownership_required"


async def test_start_blocked_without_provider_discovery(client, monkeypatch):
    wid = await _create_website(client)
    await _verify(client, monkeypatch, wid)
    r = await client.post(f"/websites/{wid}/trusted-access/start")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "provider_discovery_required"


async def test_get_not_configured_by_default(client):
    wid = await _create_website(client)
    r = await client.get(f"/websites/{wid}/trusted-access")
    assert r.status_code == 200
    assert r.json()["status"] == "not_configured"


async def test_start_get_revoke_happy_path(client, monkeypatch):
    wid = await _create_website(client)
    await _verify(client, monkeypatch, wid)
    await _discover_cloudflare(client, monkeypatch, wid)

    r = await client.post(f"/websites/{wid}/trusted-access/start")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["provider"] == "cloudflare"
    assert "Cloudflare" in body["recommended_action"]
    assert body["scanner_identity_url"] and body["verification_url"] and body["ip_ranges_url"]
    assert "guidance" in body

    g = await client.get(f"/websites/{wid}/trusted-access")
    assert g.json()["status"] == "pending"

    rv = await client.post(f"/websites/{wid}/trusted-access/revoke")
    assert rv.json()["status"] == "revoked"


async def test_other_users_website_is_404(client):
    # A website the caller doesn't own → 404 (ownership-scoped lookup).
    r = await client.get(f"/websites/{uuid.uuid4()}/trusted-access")
    assert r.status_code == 404


async def test_events_fire_and_no_secrets(client, monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(ta, "emit_trusted_access_event",
                        lambda event, website, **k: events.append(event))
    wid = await _create_website(client)
    await _verify(client, monkeypatch, wid)
    await _discover_cloudflare(client, monkeypatch, wid)
    r = await client.post(f"/websites/{wid}/trusted-access/start")
    assert ta.TRUSTED_ACCESS_STARTED in events
    assert ta.TRUSTED_ACCESS_PROVIDER_GUIDANCE in events
    blob = r.text.lower()
    for bad in ("secret", "token", "password", "api_key", "apikey"):
        assert bad not in blob
