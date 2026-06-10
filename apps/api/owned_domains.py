# WebHound — apps/api/owned_domains.py
# Neutral, dependency-light helper for the WebHound-owned/internal domain
# allowlist. Single env source: WEBHOUND_INTERNAL_SCAN_ALLOWLIST (mirrors the
# same env var + default that admin_scan's owned-domain check reads). Lifted
# here so callers (e.g. trusted_access) need not import the heavier admin_scan
# service, which pulls in the rate-limit / redis chain.

from __future__ import annotations

import os

# Keep in sync with admin_scan._DEFAULT_ALLOWLIST (the env var is the real source).
_DEFAULT_ALLOWLIST = "webhoundsecurity.com,webhound.io"


def _allowlist() -> set[str]:
    raw = os.getenv("WEBHOUND_INTERNAL_SCAN_ALLOWLIST", _DEFAULT_ALLOWLIST)
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def is_host_allowlisted(host: str) -> bool:
    """True when *host* is an explicitly allowlisted WebHound-owned/internal
    domain (exact match or subdomain)."""
    h = (host or "").strip().lower()
    allow = _allowlist()
    return h in allow or any(h == d or h.endswith("." + d) for d in allow)
