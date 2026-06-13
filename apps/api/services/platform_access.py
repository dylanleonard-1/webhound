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

# --- Audit event catalog (Phase I). Emitted via the existing provider audit
#     trail (provider_oauth.audit_event → record_phase3_event). NEVER secrets.
#     cloudflare.connected / .rule.created / .rule.removed already exist as the
#     CF_* events in cloudflare_scanner_access; the platform.* events below are
#     the framework-wide additions. ---
PA_PROVIDER_DETECTED = "platform.provider.detected"
PA_ACCESS_REQUIRED = "platform.access.required"
PA_VERIFICATION_STARTED = "platform.verification.started"
PA_VERIFICATION_SUCCESS = "platform.verification.success"
PA_VERIFICATION_FAILED = "platform.verification.failed"
PA_TICKET_CREATED = "platform.ticket.created"
PA_VERCEL_INSTRUCTIONS_SHOWN = "platform.vercel.instructions.shown"

AUDIT_EVENTS = (
    PA_PROVIDER_DETECTED, PA_ACCESS_REQUIRED, PA_VERIFICATION_STARTED,
    PA_VERIFICATION_SUCCESS, PA_VERIFICATION_FAILED, PA_TICKET_CREATED,
    PA_VERCEL_INSTRUCTIONS_SHOWN,
)


def pa_audit(db, event, website, *, user_id, org_id, status, reason=None,
             provider=None):
    """Append a platform-access audit event to the existing provider trail.
    Reuses provider_oauth.audit_event — NEVER carries tokens/secrets (only the
    event, provider name, status, and a safe reason string)."""
    from apps.api.services import provider_oauth
    provider_oauth.audit_event(
        db, event, website, provider=(provider or "platform"),
        user_id=user_id, org_id=org_id, status=status, reason=reason)


def record_access_events(db, website, view: dict, *, user_id, org_id) -> list[str]:
    """Record provider.detected + access.required for a freshly-classified view
    (called from explicit triggers — e.g. a completed scan — NOT on every read,
    to avoid trail spam). Returns the event names emitted. Safe: only the
    provider name + state, never secrets. + verification.success/failed when the
    view carries a terminal verification result."""
    emitted: list[str] = []
    provider = view.get("provider")
    if provider:
        pa_audit(db, PA_PROVIDER_DETECTED, website, user_id=user_id, org_id=org_id,
                 status="detected", reason=provider, provider=provider)
        emitted.append(PA_PROVIDER_DETECTED)
    if view.get("access_required"):
        pa_audit(db, PA_ACCESS_REQUIRED, website, user_id=user_id, org_id=org_id,
                 status="access_required", reason=provider, provider=provider)
        emitted.append(PA_ACCESS_REQUIRED)
    vr = view.get("verification")
    if vr in ("success", "partial"):
        pa_audit(db, PA_VERIFICATION_SUCCESS, website, user_id=user_id, org_id=org_id,
                 status="verified", reason=vr, provider=provider)
        emitted.append(PA_VERIFICATION_SUCCESS)
    elif vr in ("failed", "blocked"):
        pa_audit(db, PA_VERIFICATION_FAILED, website, user_id=user_id, org_id=org_id,
                 status="failed", reason=vr, provider=provider)
        emitted.append(PA_VERIFICATION_FAILED)
    return emitted


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


def build_admin_stats(
    events: list[dict], *, providers: list[dict], scanner_ips: list[str],
) -> dict:
    """Aggregate platform-access admin statistics from the audit events (rows
    from AdminAuditLog with action ∈ platform.*). Pure + testable. *events* are
    dicts with at least ``event_type`` + ``provider``.

    Returns the configured providers, the current scanner IPs, verification
    success rate, and most-common providers / failures / blocks."""
    from collections import Counter

    detected: Counter = Counter()
    failures: Counter = Counter()
    blocks: Counter = Counter()
    succ = fail = tickets = access_req = 0
    for e in events:
        et = e.get("event_type")
        prov = e.get("provider") or "unknown"
        if et == PA_PROVIDER_DETECTED:
            detected[prov] += 1
        elif et == PA_ACCESS_REQUIRED:
            access_req += 1
            blocks[prov] += 1
        elif et == PA_VERIFICATION_SUCCESS:
            succ += 1
        elif et == PA_VERIFICATION_FAILED:
            fail += 1
            failures[prov] += 1
        elif et == PA_TICKET_CREATED:
            tickets += 1

    total_verif = succ + fail
    success_rate = round(100 * succ / total_verif, 1) if total_verif else None

    def _top(c: Counter) -> list[dict]:
        return [{"provider": p, "count": n} for p, n in c.most_common(10)]

    return {
        "providers": providers,
        "provider_count": len(providers),
        "scanner_ips": list(scanner_ips),
        "verification": {
            "success": succ, "failed": fail, "total": total_verif,
            "success_rate": success_rate,
        },
        "access_required_count": access_req,
        "tickets_created": tickets,
        "most_common_providers": _top(detected),
        "most_common_failures": _top(failures),
        "most_common_blocks": _top(blocks),
    }


def registry_provider_summaries() -> list[dict]:
    """The configured providers (registry) as admin-safe summaries."""
    from apps.api.services.provider_access_registry import all_providers
    return [{
        "key": p.key, "name": p.name,
        "automation_capable": p.automation_capable,
        "allowlist_method": p.allowlist_method,
        "capabilities": list(p.capabilities),
    } for p in all_providers()]


def build_support_payload(
    view: dict, *, hostname: str, website_id: str, scan_id: str | None = None,
) -> dict:
    """Build a SAFE support-ticket payload (subject + body + category/priority)
    from a platform-access view. Auto-attaches provider, website, scan id, the
    challenge type, the access state, and the scanner IPs — NEVER tokens/secrets."""
    name = view.get("provider_name") or "an unknown provider"
    provider = view.get("provider") or "unknown"
    subject = f"[scan_blocked] Platform access — {name} blocking {hostname}"[:200]
    lines = [
        f"provider: {provider}",
        f"provider_name: {view.get('provider_name')}",
        f"wizard_state: {view.get('state')}",
        f"challenge_detected: {view.get('challenge_detected')}",
        f"access_required: {view.get('access_required')}",
        f"verification: {view.get('verification')}",
        f"allowlist_method: {view.get('allowlist_method')}",
        f"automation_capable: {view.get('automation_capable')}",
        f"website_id: {website_id}",
        f"hostname: {hostname}",
        f"scanner_ips: {', '.join(view.get('scanner_ips') or [])}",
    ]
    if scan_id:
        lines.append(f"scan_id: {scan_id}")
        lines.append(f"logs reference: scan {scan_id} on website {website_id} "
                     "— pull via Railway logs / scan_results")
    else:
        lines.append("logs reference: latest scan for this website — "
                     "pull via Railway logs / scan_results")
    return {
        "subject": subject,
        "description": "\n".join(str(line) for line in lines),
        "category": "question",
        "priority": "medium",
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
