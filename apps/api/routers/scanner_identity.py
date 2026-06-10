from __future__ import annotations

from fastapi import APIRouter

from webhound.identity import identity_dict

router = APIRouter(tags=["scanner-identity"])


@router.get("/scanner/identity")
async def get_scanner_identity() -> dict:
    """Public scanner-identity metadata so providers, customers, and security
    teams can verify legitimate WebHound traffic.

    Safe public fields only (name, version, user-agent, doc/verification/IP-range
    URLs, contact). No auth, no secrets, no internal infrastructure.
    """
    return identity_dict()
