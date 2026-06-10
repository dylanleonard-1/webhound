"""Phase 3.8 — audit & compliance (HTTP).

Drives the real Phase 3.1-3.7 flows and asserts the centralized audit trail
(reused admin_audit_log) is populated end-to-end — i.e. the record_phase3_event
calls actually fire during the endpoint flows. Writer/redaction/tenant detail is
covered by the standalone validation.
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


async def _full_flow(client, monkeypatch, wid: str) -> None:
    monkeypatch.setattr(vs, "_check_dns", _t)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    await client.post(f"/websites/{wid}/verify/check")
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    await client.post(f"/websites/{wid}/providers/discover")
    await client.post(f"/websites/{wid}/trusted-access/start")

    async def _meta(_db, _w):
        return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
                "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                     "challenge_provider": "unknown",
                                     "rendered_scripts_count": 12, "api_requests_count": 8,
                                     "evidence": []}}}, 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    await client.post(f"/websites/{wid}/access-validation/run")
    await client.post(f"/websites/{wid}/onboarding/wizard/sync")


async def test_audit_empty_before_any_action(client):
    wid = await _create(client)
    body = (await client.get(f"/websites/{wid}/audit")).json()
    assert body["audit_trail_available"] is False
    assert body["event_count"] == 0


async def test_audit_trail_populated_after_full_flow(client, monkeypatch):
    wid = await _create(client)
    await _full_flow(client, monkeypatch, wid)
    body = (await client.get(f"/websites/{wid}/audit")).json()
    assert body["audit_trail_available"] is True
    assert body["event_count"] > 0
    types = {e["event_type"] for e in body["timeline"]}
    assert "website.verification.completed" in types
    assert "provider.discovery.completed" in types
    assert any(t.startswith("trusted_access.") for t in types)
    assert "access_validation.completed" in types
    assert any(t.startswith("onboarding.") for t in types)
    assert body["last_verification"] and body["last_validation"] and body["last_provider_change"]
    # every event carries compliance tags
    assert all("SOC2" in (e["compliance_tags"] or []) for e in body["timeline"])
    # no secrets leak into the trail
    blob = (await client.get(f"/websites/{wid}/audit")).text.lower()
    for bad in ("secret", "password", "api_key", "apikey", "token"):
        assert bad not in blob


async def test_audit_other_users_website_is_404(client):
    r = await client.get(f"/websites/{uuid.uuid4()}/audit")
    assert r.status_code == 404
