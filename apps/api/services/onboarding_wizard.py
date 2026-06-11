# WebHound — apps/api/services/onboarding_wizard.py
# Phase 3.7 — Onboarding Wizard. The orchestration layer that turns the 3.1-3.6
# foundations into a single guided 6-step flow. It REUSES onboarding_readiness
# .evaluate() (which already aggregates 3.1-3.5) + the monitoring schedule, adds
# step framing / current_step / completion% / overall status, and snapshots into
# OnboardingWizardState for resume + audit + delta events. No new security or
# scanner logic; no scanner/scan_jobs changes.

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import WizardStatus
from apps.api.models.onboarding_wizard import OnboardingWizardState
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.website import Website
from apps.api.services import onboarding_readiness as ob
from apps.api.services.phase3_audit import record_phase3_event

logger = logging.getLogger(__name__)

# --- audit events (logger-backed) -------------------------------------------
ONBOARDING_STARTED = "onboarding.started"
ONBOARDING_STEP_COMPLETED = "onboarding.step.completed"
ONBOARDING_STEP_FAILED = "onboarding.step.failed"
ONBOARDING_STEP_SKIPPED = "onboarding.step.skipped"  # reserved
ONBOARDING_RESUMED = "onboarding.resumed"
ONBOARDING_COMPLETED = "onboarding.completed"
MONITORING_ACTIVATED = "monitoring.activated"

_STEPS = [
    (1, "provider_discovery", "Provider Discovery"),
    (2, "verification", "Website Verification"),
    (3, "trusted_access", "Trusted Scanner Access"),
    # Step 4 is now "connect detected providers" (CF + Vercel), not a scan-coverage
    # validation. Completion no longer requires a scan.
    (4, "providers_connected", "Connect Providers"),
    (5, "readiness", "Activation Readiness"),
    (6, "monitoring", "Monitoring Activation"),
]
_DONE = {"completed", "limited", "active"}


def _done(status: str | None) -> bool:
    return status in _DONE


def _map_verification(v: str) -> str:
    if v == "verified":
        return "completed"
    if v in ("failed", "revoked", "expired"):
        return "failed"
    return "pending"


def _map_trusted(t: str) -> str:
    return {"active": "completed", "limited": "limited"}.get(t, "pending")


def _map_providers(rv: dict) -> str:
    # DONE only when EVERY detected provider is connected (provider_connected PASS).
    # A partial connect is a hard FAIL -> 'pending' (NOT a done status), so the
    # "Providers connected" step stays unchecked and onboarding can't complete.
    return "completed" if rv["checks"].get("provider_connected") == "pass" else "pending"


def _map_readiness(s: str) -> str:
    return {"ready": "completed", "limited": "limited"}.get(s, "blocked")


def _overall(statuses: dict[str, str]) -> WizardStatus:
    if statuses["verification"] == "failed":
        return WizardStatus.FAILED
    done = [s for s in statuses.values() if _done(s)]
    if not done:
        return WizardStatus.NOT_STARTED
    if all(_done(s) for s in statuses.values()):
        if any(s == "limited" for s in statuses.values()):
            return WizardStatus.LIMITED
        return WizardStatus.COMPLETED
    return WizardStatus.IN_PROGRESS


async def compute_steps(db: AsyncSession, website: Website) -> dict:
    """Compute the 6-step wizard view by REUSING the 3.6 readiness evaluation
    (which already reads 3.1-3.5) + the monitoring schedule. Read-only."""
    rv = await ob.evaluate(db, website)  # reuse — no duplicated aggregation
    monitoring_on = await db.scalar(
        sa.select(ScanSchedule.id).where(
            ScanSchedule.website_id == website.id,
            ScanSchedule.is_enabled.is_(True),
        ).limit(1))
    statuses = {
        "provider_discovery": "completed" if rv["checks"].get("provider_discovery") == "pass" else "pending",
        "verification": _map_verification(rv["verification"]),
        "trusted_access": _map_trusted(rv["trusted_access"]),
        "providers_connected": _map_providers(rv),
        "readiness": _map_readiness(rv["status"]),
        # Monitoring counts as ACTIVE for onboarding only when readiness permits
        # (every detected provider connected). A schedule auto-enabled on verify does
        # NOT make the monitoring step active while onboarding is NOT_READY (e.g. a
        # provider still unconnected).
        "monitoring": "active" if (monitoring_on and rv["status"] != "not_ready") else "inactive",
    }
    steps = [{"step": n, "key": k, "name": name, "status": statuses[k]} for (n, k, name) in _STEPS]
    current_step = next((n for (n, k, _n) in _STEPS if not _done(statuses[k])), 6)
    percent = round(sum(1 for s in statuses.values() if _done(s)) / len(_STEPS) * 100)
    overall = _overall(statuses)
    return {
        "current_step": current_step,
        "overall_status": overall.value,
        "completion_percent": percent,
        "provider": rv["provider"],
        "steps": steps,
        "statuses": statuses,
    }


def emit_wizard_event(
    event: str, website: Website, *, provider=None, current_step=None,
    status=None, reason=None,
) -> None:
    """Single emit seam for onboarding wizard events. No secrets."""
    logger.info(
        "onboarding-wizard-event %s domain=%s provider=%s current_step=%s status=%s reason=%s",
        event, website.hostname, provider, current_step, status, reason,
    )


def dashboard_view(view: dict) -> dict:
    out = {
        "overall_status": view["overall_status"],
        "completion_percent": view["completion_percent"],
        "current_step": view["current_step"],
        "provider": view["provider"],
        "steps": view["steps"],
    }
    if view["overall_status"] == WizardStatus.LIMITED.value:
        out["notice"] = "Onboarding complete with visibility concerns — review the limited steps."
    elif view["overall_status"] == WizardStatus.FAILED.value:
        out["notice"] = "A required step failed — resolve it to continue onboarding."
    return out


async def sync_wizard(
    db: AsyncSession, website: Website, *, user_id=None, org_id=None,
) -> dict:
    """Compute the wizard view, persist the snapshot, and emit delta events
    (started/resumed/step.completed/step.failed/completed/monitoring.activated).
    Progress lives in the 3.1-3.6 records, so this never restarts onboarding."""
    view = await compute_steps(db, website)
    statuses = view["statuses"]
    provider = view["provider"]

    prior = await db.scalar(
        sa.select(OnboardingWizardState).where(OnboardingWizardState.website_id == website.id))
    prior_statuses = {} if prior is None else {
        "provider_discovery": "completed" if prior.provider else "pending",
        "verification": prior.verification_status,
        "trusted_access": prior.trusted_access_status,
        # validation_status column is reused to snapshot the providers-connected step.
        "providers_connected": prior.validation_status,
        "readiness": prior.readiness_status,
        "monitoring": prior.monitoring_status,
    }
    prior_completed = prior is not None and prior.completed_at is not None

    if prior is None:
        emit_wizard_event(ONBOARDING_STARTED, website, provider=provider,
                          current_step=view["current_step"], status=view["overall_status"])
        record_phase3_event(db, event_type=ONBOARDING_STARTED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status=view["overall_status"], resource_type="onboarding_wizard")
    elif not prior_completed:
        emit_wizard_event(ONBOARDING_RESUMED, website, provider=provider,
                          current_step=view["current_step"], status=view["overall_status"])
        record_phase3_event(db, event_type=ONBOARDING_RESUMED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status=view["overall_status"], resource_type="onboarding_wizard")

    for (_n, key, name) in _STEPS:
        new_s = statuses[key]
        old_s = prior_statuses.get(key)
        if _done(new_s) and not _done(old_s):
            emit_wizard_event(ONBOARDING_STEP_COMPLETED, website, provider=provider,
                              current_step=view["current_step"], status=new_s, reason=name)
            record_phase3_event(db, event_type=ONBOARDING_STEP_COMPLETED, website=website,
                                actor_user_id=user_id, org_id=org_id, provider=provider,
                                status=new_s, reason=name, resource_type="onboarding_wizard")
        elif new_s == "failed" and old_s != "failed":
            emit_wizard_event(ONBOARDING_STEP_FAILED, website, provider=provider,
                              current_step=view["current_step"], status=new_s, reason=name)
            record_phase3_event(db, event_type=ONBOARDING_STEP_FAILED, website=website,
                                actor_user_id=user_id, org_id=org_id, provider=provider,
                                status=new_s, reason=name, resource_type="onboarding_wizard")
        if key == "monitoring" and new_s == "active" and old_s != "active":
            emit_wizard_event(MONITORING_ACTIVATED, website, provider=provider,
                              current_step=view["current_step"], status="active")

    now = datetime.now(timezone.utc)
    is_complete = view["overall_status"] in (WizardStatus.COMPLETED.value, WizardStatus.LIMITED.value)
    if is_complete and not prior_completed:
        emit_wizard_event(ONBOARDING_COMPLETED, website, provider=provider,
                          current_step=view["current_step"], status=view["overall_status"])
        record_phase3_event(db, event_type=ONBOARDING_COMPLETED, website=website,
                            actor_user_id=user_id, org_id=org_id, provider=provider,
                            status=view["overall_status"], resource_type="onboarding_wizard")

    if prior is None:
        prior = OnboardingWizardState(website_id=website.id, domain=website.hostname)
        db.add(prior)
    prior.org_id = website.org_id
    prior.domain = website.hostname
    prior.current_step = view["current_step"]
    prior.overall_status = view["overall_status"]
    prior.provider = provider
    prior.verification_status = statuses["verification"]
    prior.trusted_access_status = statuses["trusted_access"]
    prior.validation_status = statuses["providers_connected"]  # column reused for the providers step
    prior.readiness_status = statuses["readiness"]
    prior.monitoring_status = statuses["monitoring"]
    if is_complete and prior.completed_at is None:
        prior.completed_at = now
    await db.flush()
    await db.refresh(prior)

    return dashboard_view(view)


async def get_wizard_view(db: AsyncSession, website: Website) -> dict:
    """Read-only live wizard view (no persist, no events) for the dashboard."""
    return dashboard_view(await compute_steps(db, website))
