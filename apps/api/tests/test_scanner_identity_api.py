"""Phase 3.3 — public scanner identity endpoint."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio

_SAFE_KEYS = {
    "scanner_name", "scanner_version", "user_agent",
    "verification_url", "docs_url", "ip_ranges_url", "contact",
    # Scanner egress IP/CIDR allowlist — intentionally public so customers can
    # allowlist the scanner by IP (env-configurable WEBHOUND_SCANNER_OUTBOUND_IPS).
    "outbound_ips",
}


async def test_scanner_identity_returns_safe_fields(client):
    r = await client.get("/scanner/identity")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scanner_name"] == "WebHoundScanner"
    assert body["scanner_version"] == "1.0"
    assert body["user_agent"].startswith("WebHoundScanner/1.0")
    assert "+https://webhoundsecurity.com/scanner" in body["user_agent"]
    # Exactly the safe public fields — nothing more.
    assert set(body.keys()) == _SAFE_KEYS


async def test_scanner_identity_exposes_no_secrets(client):
    blob = (await client.get("/scanner/identity")).text.lower()
    for bad in ("secret", "token", "password", "api_key", "apikey", "railway",
                "database", "redis", "stripe", "internal", "env="):
        assert bad not in blob
