# WebHound — scanner/webhound/threat_intel/urlhaus_client.py
# URLhaus provider — abuse.ch's free malware-URL feed.
#
# URLhaus offers a public POST API (`https://urlhaus-api.abuse.ch/v1/host/`)
# that returns a JSON verdict for a hostname. No API key is required for
# moderate query volumes; an Auth-Key header is supported for higher limits.
#
# This client is OFFLINE-SAFE BY DEFAULT — it raises immediately unless the
# caller explicitly opts in via ``allow_network=True``. That keeps unit tests
# and air-gapped scans deterministic. Scans that want live URLhaus enrichment
# wire it in at the EnrichmentService level.

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from .enrichment_service import BaseProvider, ProviderResult

_URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
_TAG_TO_CATEGORY = {
    "phishing": "phishing",
    "malware_download": "malware",
    "exploit": "exploit",
    "skimmer": "skimmer",
    "magecart": "skimmer",
    "credential_phish": "phishing",
    "cobalt_strike": "c2",
    "emotet": "malware",
    "redline": "malware",
}


class UrlhausClient(BaseProvider):
    """abuse.ch URLhaus provider — offline-safe by default."""

    name = "urlhaus"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        allow_network: bool = False,
        timeout: float = 6.0,
    ) -> None:
        self._api_key = api_key or os.getenv("URLHAUS_API_KEY")
        self._allow_network = allow_network
        self._timeout = timeout

    async def enrich(self, domain: str) -> ProviderResult:
        now = datetime.now(timezone.utc)
        if not self._allow_network:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now,
                error="urlhaus disabled: allow_network=False (offline mode)",
            )
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["Auth-Key"] = self._api_key
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    _URLHAUS_HOST_API,
                    data={"host": domain},
                    headers=headers,
                )
            payload = resp.json() if resp.headers.get(
                "content-type", "").startswith("application/json") else {}
            return _parse_urlhaus_response(domain, payload, now)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now, error=f"urlhaus lookup failed: {exc}",
            )


def _parse_urlhaus_response(
    domain: str, payload: dict[str, Any], checked_at: datetime,
) -> ProviderResult:
    query_status = payload.get("query_status", "")
    if query_status == "no_results":
        return ProviderResult(
            provider="urlhaus", domain=domain,
            reputation_score=0.0, confidence=0.95,
            categories=[], is_malicious=False, is_suspicious=False,
            raw=payload, checked_at=checked_at,
        )
    if query_status != "ok":
        return ProviderResult(
            provider="urlhaus", domain=domain,
            reputation_score=None, confidence=0.0,
            categories=[], is_malicious=None, is_suspicious=None,
            raw=payload, checked_at=checked_at,
            error=f"urlhaus query_status={query_status!r}",
        )
    urls = payload.get("urls") or []
    online = [u for u in urls if u.get("url_status") == "online"]
    tags: set[str] = set()
    for u in urls:
        for t in (u.get("tags") or []):
            if isinstance(t, str):
                tags.add(t.lower())
    categories = sorted({_TAG_TO_CATEGORY.get(t, t) for t in tags})
    score = 10.0 if online else (8.0 if urls else 0.0)
    return ProviderResult(
        provider="urlhaus", domain=domain,
        reputation_score=score,
        confidence=0.95 if urls else 0.85,
        categories=categories,
        is_malicious=bool(urls),
        is_suspicious=bool(urls),
        raw=payload, checked_at=checked_at,
    )
