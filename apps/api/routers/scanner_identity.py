from __future__ import annotations

from fastapi import APIRouter

from webhound.identity import identity_dict

from apps.api.config import scanner_outbound_ips

router = APIRouter(tags=["scanner-identity"])


@router.get("/scanner/identity")
async def get_scanner_identity() -> dict:
    """Public scanner-identity metadata so providers, customers, and security
    teams can verify legitimate WebHound traffic.

    Safe public fields only (name, version, user-agent, doc/verification/IP-range
    URLs, contact, and the scanner's outbound IP/CIDR allowlist). No auth, no
    secrets, no internal infrastructure. The `outbound_ips` let customers allowlist
    the scanner by IP (not UA alone) — e.g. a Vercel System Bypass Rule. The IP list
    is env-configurable (WEBHOUND_SCANNER_OUTBOUND_IPS); identity_dict() itself stays
    a pure leaf, so the IPs are merged here at the API boundary.
    """
    return {**identity_dict(), "outbound_ips": scanner_outbound_ips()}
