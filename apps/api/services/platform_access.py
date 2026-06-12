# WebHound — apps/api/services/platform_access.py
# Phase-2 Platform Access Framework: the integration layer that assembles the
# PlatformAccessWizard view from the existing systems — multi-provider block
# detection (scanner_block_detection), the provider registry (remediation +
# dynamic scanner IPs), the trusted-access state machine, and access-validation
# (Verify). The wizard UI renders this DATA ONLY — no provider logic in the
# component.
#
# Pure state machine (compute_state) + pure view builder (build_platform_access_
# view) are trivially testable; get_platform_access() gathers the live inputs.
#
# Scanner IPs always come from config.scanner_outbound_ips() — never hardcoded.

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import scanner_outbound_ips
from apps.api.models.website import Website
from apps.api.services import access_validation as av_service
from apps.api.services import trusted_access as ta_service
from apps.api.services.provider_access_registry import render_remediation
from apps.api.services.scanner_block_detection import detect_blocking_provider

# --- The 9 wizard states (the component switches on these strings only) ---
STATE_NOT_REQUIRED = "not_required"
STATE_DETECTED = "detected"
STATE_ACCESS_REQUIRED = "access_required"
STATE_CONFIGURING = "configuring"
STATE_VERIFICATION_RUNNING = "verification_running"
STATE_VERIFIED = "verified"
STATE_FAILED = "failed"
STATE_SUPPORT_REQUIRED = "support_required"
STATE_COMPLETE = "complete"

WIZARD_STATES = (
    STATE_NOT_REQUIRED, STATE_DETECTED, STATE_ACCESS_REQUIRED, STATE_CONFIGURING,
    STATE_VERIFICATION_RUNNING, STATE_VERIFIED, STATE_FAILED,
    STATE_SUPPORT_REQUIRED, STATE_COMPLETE,
)


def compute_state(
    *,
    challenge_detected: bool,
    provider: str | None,
    trusted_status: str | None,
    configuring: bool = False,
    verifying: bool = False,
    verification_result: str | None = None,   # "success" | "failed" | None
    support_required: bool = False,
) -> str:
    """Pure state machine. Precedence: explicit transient flags first, then the
    persisted trusted-access status, then the live block signal."""
    if support_required:
        return STATE_SUPPORT_REQUIRED
    if verifying:
        return STATE_VERIFICATION_RUNNING
    if verification_result in ("failed", "blocked") or trusted_status == "failed":
        return STATE_FAILED
    # "partial" = access works but coverage is restricted (LIMITED) — still
    # verified (the scanner got through), surfaced with the partial flag.
    if verification_result in ("success", "partial"):
        return STATE_VERIFIED
    if trusted_status == "active":
        return STATE_COMPLETE
    if configuring:
        return STATE_CONFIGURING
    if challenge_detected:
        return STATE_ACCESS_REQUIRED
    if provider:
        return STATE_DETECTED      # a provider is in front but not blocking now
    return STATE_NOT_REQUIRED


def build_platform_access_view(
    *,
    detection: dict,
    trusted_status: str | None,
    scanner_ips: list[str],
    configuring: bool = False,
    verifying: bool = False,
    verification_result: str | None = None,
    support_required: bool = False,
) -> dict:
    """Assemble the wizard view from a detection result + trusted status + the
    dynamic scanner IPs. Remediation is registry-driven (provider-agnostic here)."""
    provider = detection.get("provider")
    challenge = bool(detection.get("challenge_detected"))
    state = compute_state(
        challenge_detected=challenge, provider=provider, trusted_status=trusted_status,
        configuring=configuring, verifying=verifying,
        verification_result=verification_result, support_required=support_required,
    )
    remediation = render_remediation(provider, scanner_ips) if provider else None
    return {
        "state": state,
        "provider": provider,
        "provider_name": detection.get("name"),
        "automation_capable": bool(detection.get("automation_capable")),
        "allowlist_method": detection.get("allowlist_method"),
        "challenge_detected": challenge,
        "access_required": bool(detection.get("access_required")),
        "confidence": detection.get("confidence"),
        "scanner_ips": list(scanner_ips),
        "remediation": remediation,
        "verification": verification_result,
        "trusted_status": trusted_status,
        # Whether WebHound can self-serve (drives the wizard's primary CTA).
        "can_automate": bool(detection.get("automation_capable")),
        "support_url": (remediation or {}).get("support_url"),
    }


async def get_platform_access(
    db: AsyncSession, website: Website, *, cloudflare_connected: bool = False,
) -> dict:
    """Live wizard view for a website: reuse the latest access-validation result
    (browser yield + challenge detection) + the trusted-access status, run the
    registry-driven provider detection, and build the view. No new scan."""
    validation = await av_service.get_validation(db, website)
    vview = av_service.dashboard_view(validation)
    # Shape a yield-assessment-like dict for the detector from the validation.
    ya = {
        "challenge_detected": vview.get("challenge_detected") is True,
        "challenge_provider": vview.get("challenge_provider"),
    }
    detection = detect_blocking_provider(
        ya, cloudflare_connected=cloudflare_connected)

    ta = await ta_service.get_trusted_access(db, website)
    trusted_status = getattr(ta, "status", None)

    # Map the access-validation status into the wizard's verification result:
    #   ready → success (Verified) · limited → partial (Partially-Verified) ·
    #   failed → blocked when a challenge is still up, else failed · validating → running.
    vstatus = vview.get("status")
    verifying = vstatus == "validating"
    verification_result = None
    if vstatus == "ready":
        verification_result = "success"
    elif vstatus == "limited":
        verification_result = "partial"
    elif vstatus == "failed":
        verification_result = "blocked" if ya["challenge_detected"] else "failed"

    return build_platform_access_view(
        detection=detection, trusted_status=trusted_status,
        scanner_ips=scanner_outbound_ips(), verifying=verifying,
        verification_result=verification_result,
    )
