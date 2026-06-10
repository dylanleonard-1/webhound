"""Phase 3.5 — access validation foundation (HTTP).

State is set up through the client's own flows (verify + discover + trusted
access). The latest-scan metadata is mocked at the service seam so the endpoint
/ classification / persistence / trusted-access drive run for real. Deeper
classification (ready/limited/failed) is covered by the standalone validation.
"""
from __future__ import annotations

import uuid

import pytest

from apps.api.services import access_validation as av
from apps.api.services import verification as vs

pytestmark = pytest.mark.anyio


async def _always_true(*_a, **_k) -> bool:
    return True


async def _create(client, url: str = "https://example.com") -> str:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _verify(client, monkeypatch, wid: str) -> None:
    monkeypatch.setattr(vs, "_check_dns", _always_true)
    await client.post(f"/websites/{wid}/verify/initiate?method=dns_txt")
    assert (await client.post(f"/websites/{wid}/verify/check")).json()["verified"] is True


async def _discover(client, monkeypatch, wid: str) -> None:
    from webhound.providers.discovery import ProviderDiscoveryService, ProviderProfile

    async def _fake(self, url, *, on_event=None):
        return ProviderProfile(domain="example.com", cdn_provider="Cloudflare",
                               waf_provider="Cloudflare", confidence=95, evidence=[])

    monkeypatch.setattr(ProviderDiscoveryService, "discover", _fake)
    assert (await client.post(f"/websites/{wid}/providers/discover")).status_code == 200


async def _start_trusted_access(client, wid: str) -> None:
    assert (await client.post(f"/websites/{wid}/trusted-access/start")).status_code == 200


def _ready_meta() -> dict:
    return {"browser_pass": {"deferred": False, "browser_pages_rendered": 5,
            "yield_assessment": {"rendered_real_app": True, "challenge_detected": False,
                                 "challenge_provider": "unknown",
                                 "rendered_scripts_count": 12, "api_requests_count": 8,
                                 "evidence": []}}}


async def test_run_blocked_when_unverified(client):
    wid = await _create(client)
    r = await client.post(f"/websites/{wid}/access-validation/run")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "ownership_required"


async def test_run_blocked_without_trusted_access(client, monkeypatch):
    wid = await _create(client)
    await _verify(client, monkeypatch, wid)
    r = await client.post(f"/websites/{wid}/access-validation/run")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "trusted_access_required"


async def test_get_pending_by_default(client):
    wid = await _create(client)
    r = await client.get(f"/websites/{wid}/access-validation")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


async def test_run_ready_drives_trusted_access_active(client, monkeypatch):
    wid = await _create(client)
    await _verify(client, monkeypatch, wid)
    await _discover(client, monkeypatch, wid)
    await _start_trusted_access(client, wid)

    async def _meta(_db, _website):
        return _ready_meta(), 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    r = await client.post(f"/websites/{wid}/access-validation/run")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ready"
    assert body["browser_rendered"] is True
    assert body["challenge_detected"] is False
    assert body["pages_found"] == 10
    assert body["recommendation"]

    # Validation drove the trusted-access status to active.
    ta = await client.get(f"/websites/{wid}/trusted-access")
    assert ta.json()["status"] == "active"


async def test_other_users_website_is_404(client):
    r = await client.get(f"/websites/{uuid.uuid4()}/access-validation")
    assert r.status_code == 404


async def test_events_fire_and_no_secrets(client, monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(av, "emit_validation_event",
                        lambda event, website, **k: events.append(event))
    wid = await _create(client)
    await _verify(client, monkeypatch, wid)
    await _discover(client, monkeypatch, wid)
    await _start_trusted_access(client, wid)

    async def _meta(_db, _website):
        return _ready_meta(), 10

    monkeypatch.setattr(av, "_latest_scan_metadata", _meta)
    r = await client.post(f"/websites/{wid}/access-validation/run")
    assert av.VALIDATION_STARTED in events
    assert av.VALIDATION_COMPLETED in events
    assert av.VALIDATION_READY in events
    blob = r.text.lower()
    for bad in ("secret", "token", "password", "api_key", "apikey"):
        assert bad not in blob
