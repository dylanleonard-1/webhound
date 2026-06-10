# WebHound — scanner/webhound/identity.py
# Phase 3.3 — Scanner Identity (single source of truth).
#
# This is the ONE place WebHound's public scanner identity is defined. The
# scanner HTTP client and browser runner derive their User-Agent from here, and
# the API's GET /scanner/identity endpoint serves identity_dict(). Kept
# leaf-level (imports nothing from webhound) so every layer can consume it
# without a cycle.
#
# PUBLIC / SAFE ONLY — never put secrets, internal infrastructure, deployment
# details, or env values in this module.

from __future__ import annotations

SCANNER_NAME = "WebHoundScanner"
SCANNER_VERSION = "1.0"

_SITE = "https://webhoundsecurity.com"

# The standardized User-Agent for ALL scanner outbound traffic. The "+URL" lets
# anyone who sees WebHound in their logs reach the public identity page. This is
# honest self-identification — never spoof a browser or another crawler.
SCANNER_USER_AGENT = f"{SCANNER_NAME}/{SCANNER_VERSION} (+{_SITE}/scanner)"

SCANNER_DOCS_URL = f"{_SITE}/scanner"
SCANNER_VERIFICATION_URL = f"{_SITE}/verification"
SCANNER_IP_RANGES_URL = f"{_SITE}/ip-ranges"
SCANNER_CONTACT = "security@webhoundsecurity.com"

# Reserved audit-event name — emitted if/when scanner identity becomes
# runtime-configurable. Today the identity ships as code (it changes via a
# deploy), so there is no runtime "update" to record yet.
SCANNER_IDENTITY_UPDATED = "scanner.identity.updated"


def identity_dict() -> dict[str, str]:
    """Safe, public scanner-identity metadata.

    Contains no secrets, no internal infrastructure, no env. Served verbatim by
    ``GET /scanner/identity`` and stamped into scan metadata for telemetry.
    """
    return {
        "scanner_name": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "user_agent": SCANNER_USER_AGENT,
        "verification_url": SCANNER_VERIFICATION_URL,
        "docs_url": SCANNER_DOCS_URL,
        "ip_ranges_url": SCANNER_IP_RANGES_URL,
        "contact": SCANNER_CONTACT,
    }
