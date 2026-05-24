# WebHound — scanner/webhound/threat_intel/virustotal_client.py
# VirusTotal v3 provider for domain reputation.
#
# VirusTotal's domains endpoint (GET /api/v3/domains/{domain}) requires an
# API key (free tier: 4 requests/minute, 500/day). Without a key, this
# client returns an error ProviderResult.
#
# OFFLINE-SAFE BY DEFAULT: the client raises immediately unless the caller
# passes ``allow_network=True``. Reads the API key from the VIRUSTOTAL_API_KEY
# env var or the explicit constructor argument.

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from .enrichment_service import BaseProvider, ProviderResult

_VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"


class VirusTotalClient(BaseProvider):
    """VirusTotal v3 domain-reputation provider — offline-safe by default."""

    name = "virustotal"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        allow_network: bool = False,
        timeout: float = 6.0,
    ) -> None:
        self._api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
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
                error="virustotal disabled: allow_network=False (offline mode)",
            )
        if not self._api_key:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now,
                error="virustotal: no API key (set VIRUSTOTAL_API_KEY)",
            )
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        url = _VT_DOMAIN_API.format(domain=domain)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=headers)
            payload = resp.json() if resp.headers.get(
                "content-type", "").startswith("application/json") else {}
            return _parse_vt_response(domain, payload, now)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now, error=f"virustotal lookup failed: {exc}",
            )


def _parse_vt_response(
    domain: str, payload: dict[str, Any], checked_at: datetime,
) -> ProviderResult:
    data = (payload.get("data") or {}).get("attributes") or {}
    stats = data.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return ProviderResult(
            provider="virustotal", domain=domain,
            reputation_score=None, confidence=0.0,
            categories=[], is_malicious=None, is_suspicious=None,
            raw=payload, checked_at=checked_at,
            error="virustotal: no analysis stats in response",
        )
    # VT-style normalisation: malicious + suspicious detection ratio maps to 0–10.
    detect_ratio = (malicious + suspicious) / total
    rep_score = round(detect_ratio * 10.0, 2)
    categories_dict = data.get("categories") or {}
    categories = sorted({str(v).lower() for v in categories_dict.values()
                         if isinstance(v, str)})
    return ProviderResult(
        provider="virustotal", domain=domain,
        reputation_score=rep_score,
        confidence=0.9 if total >= 20 else 0.7,
        categories=categories,
        is_malicious=malicious >= 2,
        is_suspicious=(malicious + suspicious) >= 1,
        raw=payload, checked_at=checked_at,
    )
