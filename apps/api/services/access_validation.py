# WebHound — apps/api/services/access_validation.py
# Phase 3.5 — Access Validation foundation. Answers "can WebHound actually see
# the site?" by CONSUMING existing scan metadata (browser yield / challenge /
# discovery counts) — it runs no new scanner and creates no second challenge
# detector. It classifies READY / LIMITED / FAILED, persists the result, and
# drives the Phase-3.4 trusted-access status. No scanner/WADE/scoring changes.

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.access_validation import AccessValidationResult
from apps.api.models.enums import AccessValidationStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website
from apps.api.services import trusted_access as ta_service
from apps.api.services.phase3_audit import record_phase3_event
from apps.api.services.verification import is_ownership_verified

logger = logging.getLogger(__name__)

# --- audit events (logger-backed; reuse the existing log pipeline) ----------
VALIDATION_STARTED = "access_validation.started"
VALIDATION_COMPLETED = "access_validation.completed"
VALIDATION_LIMITED = "access_validation.limited"
VALIDATION_FAILED = "access_validation.failed"
VALIDATION_CHALLENGE_DETECTED = "challenge.detected"
VALIDATION_READY = "validation.ready"


class OwnershipRequiredError(Exception):
    code = "ownership_required"


class TrustedAccessRequiredError(Exception):
    code = "trusted_access_required"


def emit_validation_event(
    event: str, website: Website, *, provider=None, status=None, reason=None,
) -> None:
    """Single emit seam for access_validation.* / challenge.detected events.
    Never logs secrets (none exist here)."""
    logger.info(
        "access-validation-event %s domain=%s provider=%s status=%s reason=%s",
        event, website.hostname, provider, status, reason,
    )


async def _latest_scan_metadata(db: AsyncSession, website: Website) -> tuple[dict | None, int]:
    """The most recent scan's metadata + pages_crawled for this website, or
    (None, 0) when no scan exists yet. Consumes existing output — runs nothing."""
    row = await db.scalar(
        sa.select(ScanResultRecord)
        .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
        .where(ScanJob.website_id == website.id)
        .order_by(ScanResultRecord.created_at.desc())
        .limit(1)
    )
    if row is None:
        return None, 0
    return (row.scanner_metadata or {}), int(row.pages_crawled or 0)


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _classify(
    *, browser_pass_present: bool, rendered_real_app, challenge_detected, pages_found: int,
) -> AccessValidationStatus:
    """Map the (already-computed) browser yield assessment to a validation
    status — reuses the single source of truth rather than re-deciding."""
    if challenge_detected is True:
        return (AccessValidationStatus.FAILED if rendered_real_app is False
                else AccessValidationStatus.LIMITED)
    if rendered_real_app is True:
        return AccessValidationStatus.READY
    if rendered_real_app is False:
        return AccessValidationStatus.FAILED
    # rendered_real_app unknown (or no browser evidence)
    if not browser_pass_present:
        return AccessValidationStatus.LIMITED if pages_found > 0 else AccessValidationStatus.FAILED
    return AccessValidationStatus.LIMITED


_RECOMMEND = {
    AccessValidationStatus.READY.value: "Coverage looks healthy — monitoring and deep scans can proceed.",
    AccessValidationStatus.LIMITED.value: "Visibility is restricted — complete trusted scanner access setup to improve coverage.",
    AccessValidationStatus.FAILED.value: "Scanner cannot reliably see the site — complete trusted scanner access, then re-validate.",
    AccessValidationStatus.PENDING.value: "Run a scan, then validate access.",
    AccessValidationStatus.VALIDATING.value: "Validation in progress.",
}


def dashboard_view(result: AccessValidationResult | None) -> dict:
    if result is None:
        return {
            "status": AccessValidationStatus.PENDING.value,
            "pages_found": 0, "scripts_found": 0, "apis_found": 0,
            "third_parties_found": 0, "browser_rendered": False,
            "challenge_detected": None, "challenge_provider": None,
            "validated_at": None,
            "recommendation": _RECOMMEND[AccessValidationStatus.PENDING.value],
        }
    return {
        "status": result.validation_status,
        "pages_found": result.pages_found,
        "scripts_found": result.scripts_found,
        "apis_found": result.apis_found,
        "third_parties_found": result.third_parties_found,
        "browser_rendered": result.browser_rendered,
        "challenge_detected": result.challenge_detected,
        "challenge_provider": result.challenge_provider,
        "validated_at": result.validated_at,
        "recommendation": _RECOMMEND.get(result.validation_status, ""),
    }


async def get_validation(db: AsyncSession, website: Website) -> AccessValidationResult | None:
    return await db.scalar(
        sa.select(AccessValidationResult).where(
            AccessValidationResult.website_id == website.id
        )
    )


async def _upsert(db, website, **fields) -> AccessValidationResult:
    result = await get_validation(db, website)
    if result is None:
        result = AccessValidationResult(website_id=website.id, domain=website.hostname)
        db.add(result)
    result.org_id = website.org_id
    result.domain = website.hostname
    for k, v in fields.items():
        setattr(result, k, v)
    await db.flush()
    await db.refresh(result)
    return result


async def validate_access(
    db: AsyncSession, website: Website, *, user_id=None, org_id=None,
) -> AccessValidationResult:
    """Validate visibility from the latest scan's metadata; persist the result
    and drive the trusted-access status. Reuses browser yield + challenge
    detection as the single source of truth."""
    if not is_ownership_verified(website):
        raise OwnershipRequiredError()
    ta_profile = await ta_service.get_trusted_access(db, website)
    if ta_profile is None:
        raise TrustedAccessRequiredError()

    emit_validation_event(VALIDATION_STARTED, website, provider=ta_profile.provider,
                          status=AccessValidationStatus.VALIDATING.value)

    metadata, pages_found = await _latest_scan_metadata(db, website)
    now = datetime.now(timezone.utc)

    if not metadata:
        # Nothing to consume yet — stay pending (don't touch trusted access).
        result = await _upsert(
            db, website,
            validation_status=AccessValidationStatus.PENDING.value,
            pages_found=0, scripts_found=0, apis_found=0, third_parties_found=0,
            browser_rendered=False, challenge_detected=None, challenge_provider=None,
            evidence=["no scan evidence yet — run a scan to validate access"],
            validated_at=None,
        )
        emit_validation_event(VALIDATION_COMPLETED, website, provider=ta_profile.provider,
                              status=result.validation_status, reason="no_scan_evidence")
        record_phase3_event(
            db, event_type=VALIDATION_COMPLETED, website=website, actor_user_id=user_id,
            org_id=org_id, provider=ta_profile.provider, status=result.validation_status,
            reason="no_scan_evidence", resource_type="access_validation", resource_id=result.id)
        return result

    # Reuse the SINGLE source of truth: the browser yield assessment the
    # scanner's challenge_detection produced during the scan and persisted on
    # metadata.browser_pass.yield_assessment. We read it directly (no second
    # detector, no heavy reporting import).
    bp = metadata.get("browser_pass") if isinstance(metadata, dict) else None
    bp = bp if isinstance(bp, dict) else None
    browser_pass_present = bp is not None
    ya = bp.get("yield_assessment") if bp else None
    ya = ya if isinstance(ya, dict) else None
    browser_rendered = bool(
        browser_pass_present and not bp.get("deferred")
        and _int(bp.get("browser_pages_rendered")) > 0
    )

    rendered_real_app = ya.get("rendered_real_app") if ya else None
    challenge_raw = ya.get("challenge_detected") if ya else None
    challenge_detected = True if challenge_raw is True else (False if challenge_raw is False else None)
    challenge_provider = ya.get("challenge_provider") if ya else None
    scripts_found = _int(ya.get("rendered_scripts_count")) if ya else 0
    apis_found = _int(ya.get("api_requests_count")) if ya else 0
    third_parties_found = _int(
        (metadata.get("threat_intel_coverage") or {}).get("hosts_total")
    )

    status = _classify(
        browser_pass_present=browser_pass_present,
        rendered_real_app=rendered_real_app,
        challenge_detected=challenge_detected, pages_found=pages_found)

    evidence: list[str] = []
    evidence.append(f"browser rendered: {browser_rendered}")
    evidence.append(f"pages discovered: {pages_found}")
    if challenge_detected:
        evidence.append(f"challenge detected: {challenge_provider}")
    elif ya:
        evidence.append("challenge not detected")
    if ya and ya.get("evidence"):
        evidence.extend(str(e) for e in (ya["evidence"] or [])[:5])

    result = await _upsert(
        db, website,
        validation_status=status.value,
        pages_found=pages_found, scripts_found=scripts_found,
        apis_found=apis_found, third_parties_found=third_parties_found,
        browser_rendered=browser_rendered, challenge_detected=challenge_detected,
        challenge_provider=challenge_provider, evidence=evidence, validated_at=now,
    )

    # Events.
    if challenge_detected:
        emit_validation_event(VALIDATION_CHALLENGE_DETECTED, website,
                              provider=challenge_provider, status=status.value)
        record_phase3_event(
            db, event_type=VALIDATION_CHALLENGE_DETECTED, website=website,
            actor_user_id=user_id, org_id=org_id, provider=challenge_provider,
            status=status.value, resource_type="access_validation", resource_id=result.id)
    emit_validation_event(VALIDATION_COMPLETED, website, provider=ta_profile.provider,
                          status=status.value)
    record_phase3_event(
        db, event_type=VALIDATION_COMPLETED, website=website, actor_user_id=user_id,
        org_id=org_id, provider=ta_profile.provider, status=status.value,
        resource_type="access_validation", resource_id=result.id)
    if status is AccessValidationStatus.READY:
        emit_validation_event(VALIDATION_READY, website, provider=ta_profile.provider,
                              status=status.value)
    elif status is AccessValidationStatus.LIMITED:
        emit_validation_event(VALIDATION_LIMITED, website, provider=ta_profile.provider,
                              status=status.value)
    elif status is AccessValidationStatus.FAILED:
        emit_validation_event(VALIDATION_FAILED, website, provider=ta_profile.provider,
                              status=status.value)

    # Drive the Phase-3.4 trusted-access status (the documented seam).
    reason = f"access_validation:{status.value}"
    if status is AccessValidationStatus.READY:
        await ta_service.mark_active(db, website, ta_profile, reason=reason,
                                     user_id=user_id, org_id=org_id)
    elif status is AccessValidationStatus.LIMITED:
        await ta_service.mark_limited(db, website, ta_profile, reason=reason,
                                      user_id=user_id, org_id=org_id)
    elif status is AccessValidationStatus.FAILED:
        await ta_service.mark_failed(db, website, ta_profile, reason=reason,
                                     user_id=user_id, org_id=org_id)

    return result
