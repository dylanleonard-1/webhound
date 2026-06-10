# WebHound — apps/api/services/onboarding_automation.py
# Phase 3.10 — Onboarding Automation. The central conductor that runs the
# Phase 3.1-3.9 services in sequence, automatically advancing as far as it can
# WITHOUT customer action, then pausing at the customer gates (ownership
# verification, awaiting a scan) with clear guidance.
#
# It performs none of the work itself — it only orchestrates existing services —
# and it NEVER bypasses verification, trusted access, or readiness, and never
# modifies customer infrastructure. Re-running resumes from where it stopped:
# progress lives in the reused per-phase records + the Phase 3.7 wizard state,
# so there is no new state model and onboarding never restarts.

from __future__ import annotations

import logging

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import VerificationMethod
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.website import Website
from apps.api.services import access_validation as av_service
from apps.api.services import onboarding_readiness as ob_service
from apps.api.services import onboarding_wizard as wiz_service
from apps.api.services import provider_discovery as pd_service
from apps.api.services import trusted_access as ta_service
from apps.api.services import verification as vs_service
from apps.api.services.phase3_audit import record_phase3_event

logger = logging.getLogger(__name__)

AUTOMATION_STARTED = "automation.started"
AUTOMATION_STAGE_STARTED = "automation.stage.started"
AUTOMATION_STAGE_COMPLETED = "automation.stage.completed"
AUTOMATION_STAGE_FAILED = "automation.stage.failed"
AUTOMATION_RESUMED = "automation.resumed"
AUTOMATION_COMPLETED = "automation.completed"
MONITORING_AUTO_ACTIVATED = "monitoring.auto_activated"
DEEP_SCAN_AUTO_ENABLED = "deep_scan.auto_enabled"


def _emit(event: str, website: Website, *, provider=None, stage=None, status=None, reason=None) -> None:
    logger.info(
        "automation-event %s domain=%s provider=%s stage=%s status=%s reason=%s",
        event, website.hostname, provider, stage, status, reason)


def _state(*, current_stage: str, status: str, completed_stages: list[str],
           provider: str | None = None, next_action: str | None = None) -> dict:
    return {
        "current_stage": current_stage,
        "status": status,
        "completed_stages": completed_stages,
        "provider": provider,
        "next_action": next_action,
    }


async def run_automation(
    db: AsyncSession, website: Website, *, user_id=None, org_id=None,
) -> dict:
    """Drive onboarding automatically as far as possible; pause at customer
    gates. Idempotent + resumable. Returns the automation state."""
    completed: list[str] = []
    pp = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id))
    resumed = pp is not None  # provider already discovered => we've run before

    started_event = AUTOMATION_RESUMED if resumed else AUTOMATION_STARTED
    _emit(started_event, website, status="running")
    record_phase3_event(db, event_type=started_event, website=website,
                        actor_user_id=user_id, org_id=org_id, status="running")

    # --- Stage 1: provider discovery (fully automatable) -------------------
    if pp is None:
        _emit(AUTOMATION_STAGE_STARTED, website, stage="provider_discovery")
        try:
            pp = await pd_service.run_provider_discovery(db, website)
        except Exception as exc:  # noqa: BLE001 — automation must never crash the request
            logger.exception("automation: provider discovery failed for %s", website.hostname)
            _emit(AUTOMATION_STAGE_FAILED, website, stage="provider_discovery", reason=str(exc)[:120])
            record_phase3_event(db, event_type=AUTOMATION_STAGE_FAILED, website=website,
                                actor_user_id=user_id, org_id=org_id, status="failed",
                                reason="provider_discovery_error")
            return _state(current_stage="provider_discovery", status="failed",
                          completed_stages=completed, next_action="Retry automation")
        _emit(AUTOMATION_STAGE_COMPLETED, website, stage="provider_discovery")
    provider = (pp.cdn_provider or pp.waf_provider or pp.hosting_provider or pp.cms) if pp else None
    completed.append("provider_discovery")

    # --- Stage 2: verification (CUSTOMER gate — route + pause, never bypass) -
    if not vs_service.is_ownership_verified(website):
        rec = vs_service.recommend_verification(pp)
        method = VerificationMethod(rec["recommended_method"])
        await vs_service.get_or_create_verification(db, website, method)  # ensure a token exists
        _emit(AUTOMATION_STAGE_STARTED, website, stage="verification",
              status="awaiting_verification", reason=method.value)
        record_phase3_event(db, event_type=AUTOMATION_STAGE_STARTED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status="awaiting_verification", reason=f"verification:{method.value}")
        await wiz_service.sync_wizard(db, website, user_id=user_id, org_id=org_id)
        return _state(current_stage="verification", status="awaiting_verification",
                      completed_stages=completed, provider=provider,
                      next_action=f"Verify domain ownership (recommended: {method.value})")
    completed.append("verification")

    # --- Stage 3: trusted access (auto-start guidance; no infra change) ------
    ta = await ta_service.get_trusted_access(db, website)
    if ta is None:
        _emit(AUTOMATION_STAGE_STARTED, website, stage="trusted_access")
        ta, _guidance = await ta_service.start_trusted_access(
            db, website, user_id=user_id, org_id=org_id)
        _emit(AUTOMATION_STAGE_COMPLETED, website, stage="trusted_access", status=ta.access_status)
    completed.append("trusted_access")

    # --- Stage 4: access validation (needs an existing scan) ----------------
    # Reuse 3.5, which returns status 'pending' when there is no scan evidence.
    result = await av_service.validate_access(db, website, user_id=user_id, org_id=org_id)
    if result.validation_status == "pending":
        _emit(AUTOMATION_STAGE_STARTED, website, stage="validation", status="awaiting_scan")
        record_phase3_event(db, event_type=AUTOMATION_STAGE_STARTED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status="awaiting_scan", reason="validation:no_scan_evidence")
        await wiz_service.sync_wizard(db, website, user_id=user_id, org_id=org_id)
        return _state(current_stage="validation", status="awaiting_scan",
                      completed_stages=completed, provider=provider,
                      next_action="Run a scan to validate scanner visibility")
    _emit(AUTOMATION_STAGE_COMPLETED, website, stage="validation", status=result.validation_status)
    completed.append("validation")

    # --- Stages 5 + 6: readiness + monitoring activation (auto) -------------
    try:
        await ob_service.activate_monitoring(db, website, user_id=user_id, org_id=org_id)
    except ob_service.NotReadyError:
        _emit(AUTOMATION_STAGE_FAILED, website, stage="monitoring", status="not_ready")
        record_phase3_event(db, event_type=AUTOMATION_STAGE_FAILED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status="not_ready", reason="monitoring:not_ready")
        completed.append("readiness")
        await wiz_service.sync_wizard(db, website, user_id=user_id, org_id=org_id)
        _emit(AUTOMATION_COMPLETED, website, provider=provider, status="not_ready")
        return _state(current_stage="readiness", status="not_ready",
                      completed_stages=completed, provider=provider,
                      next_action="Resolve onboarding gaps, then re-run automation")
    completed += ["readiness", "monitoring"]
    for ev, st in ((MONITORING_AUTO_ACTIVATED, "active"), (DEEP_SCAN_AUTO_ENABLED, "enabled")):
        _emit(ev, website, provider=provider, status=st)
        record_phase3_event(db, event_type=ev, website=website, actor_user_id=user_id,
                            org_id=org_id, provider=provider, status=st)

    await wiz_service.sync_wizard(db, website, user_id=user_id, org_id=org_id)
    _emit(AUTOMATION_COMPLETED, website, provider=provider, status="completed")
    record_phase3_event(db, event_type=AUTOMATION_COMPLETED, website=website,
                        actor_user_id=user_id, org_id=org_id, provider=provider, status="completed")
    return _state(current_stage="monitoring", status="completed",
                  completed_stages=completed, provider=provider, next_action=None)
