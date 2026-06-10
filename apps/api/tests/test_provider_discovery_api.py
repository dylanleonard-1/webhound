"""Phase 3.1 — provider discovery API tests.

The scanner's network discovery is mocked at the ProviderDiscoveryService.discover
seam; the endpoint, service upsert, persistence, and schema are exercised for real.
"""
from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.anyio

_SUCCESS_FIELDS = (
    "registrar", "dns_provider", "hosting_provider", "cdn_provider",
    "waf_provider", "cms", "framework", "confidence", "evidence", "domain",
)


async def _create_website(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture
def _mock_discovery(monkeypatch):
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake_discover(self, url, *, on_event=None):
        if on_event:
            on_event("provider.discovery.completed", {"domain": "example.com"})
        return ProviderProfile(
            domain="example.com",
            dns_provider="Cloudflare",
            cdn_provider="Cloudflare",
            waf_provider="Cloudflare",
            cms="WordPress",
            framework="Next.js",
            confidence=84,
            evidence=["cdn_provider: Cloudflare (technology engine)"],
        )

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake_discover)


async def test_discover_returns_provider_profile(client, _mock_discovery):
    wid = await _create_website(client)
    r = await client.post(f"/websites/{wid}/providers/discover")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cdn_provider"] == "Cloudflare"
    assert body["framework"] == "Next.js"
    assert body["confidence"] == 84
    assert body["domain"] == "example.com"
    for key in _SUCCESS_FIELDS:
        assert key in body


async def test_discovery_is_persisted_and_returned_by_get(client, _mock_discovery):
    wid = await _create_website(client)
    await client.post(f"/websites/{wid}/providers/discover")
    r = await client.get(f"/websites/{wid}/providers")
    assert r.status_code == 200, r.text
    assert r.json()["dns_provider"] == "Cloudflare"


async def test_rediscovery_updates_in_place(client, _mock_discovery):
    wid = await _create_website(client)
    r1 = await client.post(f"/websites/{wid}/providers/discover")
    r2 = await client.post(f"/websites/{wid}/providers/discover")
    # 1:1 — same profile id, refreshed (no duplicate row).
    assert r1.json()["id"] == r2.json()["id"]


async def test_get_before_discovery_is_404(client):
    wid = await _create_website(client)
    r = await client.get(f"/websites/{wid}/providers")
    assert r.status_code == 404


async def test_discover_unknown_website_is_404(client, _mock_discovery):
    r = await client.post(f"/websites/{uuid.uuid4()}/providers/discover")
    assert r.status_code == 404
