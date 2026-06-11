# WebHound — apps/api/services/cloudflare_telemetry.py
# Phase 3.4 scanner-access — FOUNDATION-ONLY security telemetry reads using the
# elevated token's read scopes (Security Center Insights, Page Shield). Best-effort:
# a product that isn't enabled on the zone simply reports unavailable; telemetry
# never blocks the scanner-access flow. NEVER logs the token.

from __future__ import annotations

import httpx

_CF_API = "https://api.cloudflare.com/client/v4"


async def _try_count(client: httpx.AsyncClient, url: str) -> dict:
    """GET a read-only telemetry endpoint and return {available, count} without
    raising — a 403/404 (product off / scope absent) just reports available=False."""
    try:
        r = await client.get(url)
    except Exception:  # noqa: BLE001 — network hiccup must not break the flow
        return {"available": False, "count": None}
    if r.is_error:
        return {"available": False, "count": None}
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        return {"available": True, "count": None}
    result = body.get("result") if isinstance(body, dict) else None
    count = len(result) if isinstance(result, list) else None
    # Prefer the API's own total_count when present (paginated endpoints).
    info = (body.get("result_info") or {}) if isinstance(body, dict) else {}
    if isinstance(info, dict) and isinstance(info.get("total_count"), int):
        count = info["total_count"]
    return {"available": True, "count": count}


async def read_security_telemetry(access_token: str, zone_id: str) -> dict:
    """Read a minimal, non-secret security-telemetry snapshot for the zone. Returns
    a compact summary (availability + counts) suitable for storing/exposing. Purely
    a foundation for future intelligence — does not interpret or alert."""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        page_shield = await _try_count(
            client, f"{_CF_API}/zones/{zone_id}/page_shield/scripts?per_page=1")
        security_center = await _try_count(
            client, f"{_CF_API}/zones/{zone_id}/security-center/insights?per_page=1")
    return {
        "page_shield_scripts": page_shield,
        "security_center_insights": security_center,
    }
