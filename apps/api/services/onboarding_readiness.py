# WebHound — apps/api/services/onboarding_readiness.py
# Phase 3.6 — Onboarding Readiness & Activation. A simple activation DECISION
# layer that AGGREGATES the 3.1-3.5 signals (provider discovery, verification,
# trusted access, access validation) into READY / LIMITED / NOT_READY and the
# monitoring/deep-scan/baseline allow flags. It reuses existing data only — no
# new discovery/scoring/telemetry engine, and it does NOT modify scanner logic,
# scan_jobs, or the existing auto-monitoring behaviour. The only thing it
# *enacts* is enabling monitoring (its schedule) when readiness permits.

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.access_validation import AccessValidationResult
from apps.api.models.enums import (
    OnboardingReadinessStatus,
    ReadinessCheck,
    TrustedAccessStatus,
    VerificationStatus,
)
from apps.api.models.enums import ProviderConnectionStatus
from apps.api.models.onboarding_readiness import OnboardingReadiness
from apps.api.models.provider_connection import ProviderConnection
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.trusted_access import TrustedAccessProfile
from apps.api.models.website import Website
from apps.api.services.phase3_audit import record_phase3_event

logger = logging.getLogger(__name__)

# Supported OAuth-connectable providers. Completion = every DETECTED supported
# provider is CONNECTED (a CF+Vercel site needs both; a CF-only site needs CF).
_SUPPORTED_PROVIDERS = ("cloudflare", "vercel")

# --- audit events (logger-backed; reuse the existing log pipeline) ----------
ONBOARDING_STARTED = "onboarding.started"
ONBOARDING_CHECK_COMPLETED = "onboarding.check.completed"
ONBOARDING_READY = "onboarding.ready"
ONBOARDING_LIMITED = "onboarding.limited"
ONBOARDING_BLOCKED = "onboarding.blocked"
MONITORING_ACTIVATION_ALLOWED = "monitoring.activation.allowed"
MONITORING_ACTIVATION_BLOCKED = "monitoring.activation.blocked"
DEEP_SCAN_ACTIVATION_ALLOWED = "deep_scan.activation.allowed"
DEEP_SCAN_ACTIVATION_BLOCKED = "deep_scan.activation.blocked"

_PASS, _WARN, _FAIL = ReadinessCheck.PASS, ReadinessCheck.WARNING, ReadinessCheck.FAIL
# Completion now depends on PROVIDER CONNECTIONS, not a scan. access_validation is
# demoted to a post-completion coverage/quality signal (returned, but NOT a hard gate).
_HARD_CHECKS = ("provider_discovery", "website_verified", "trusted_access", "provider_connected")


def detected_supported_providers(pp: ProviderProfile | None) -> set[str]:
    """The supported providers DETECTED in the environment (from ProviderProfile)."""
    if pp is None:
        return set()
    blob = " ".join(str(x or "").lower() for x in
                    (pp.cdn_provider, pp.waf_provider, pp.dns_provider, pp.hosting_provider))
    return {p for p in _SUPPORTED_PROVIDERS if p in blob}


def provider_connected_check(
    detected: set[str], connected: set[str], *, verified: bool,
) -> ReadinessCheck:
    """PASS only when EVERY detected supported provider is connected. ANY missing
    provider is a HARD FAIL (partial connect must NOT complete onboarding) — a
    1-of-2 connect blocks completion until the second provider is connected. When
    NONE is detected (unsupported provider), 'connected' falls back to ownership
    verified (manual DNS path)."""
    if not detected:
        return _PASS if verified else _FAIL
    # Any detected provider not yet connected -> hard FAIL (NOT a warning).
    return _PASS if detected.issubset(connected) else _FAIL


class NotReadyError(Exception):
    """Activation blocked because the website is NOT_READY."""
    code = "not_ready"


def emit_onboarding_event(
    event: str, website: Website, *, provider=None, status=None, reason=None,
) -> None:
    """Single emit seam for onboarding/activation audit events. No secrets."""
    logger.info(
        "onboarding-event %s domain=%s provider=%s status=%s reason=%s",
        event, website.hostname, provider, status, reason,
    )


def _provider_label(ta: TrustedAccessProfile | None, pp: ProviderProfile | None) -> str | None:
    if ta is not None and ta.provider:
        return ta.provider
    if pp is not None:
        return pp.cdn_provider or pp.waf_provider or pp.hosting_provider or pp.cms
    return None


async def evaluate(db: AsyncSession, website: Website) -> dict:
    """Pure computation (DB reads only — no persist, no events): aggregate the
    3.1-3.5 signals into a readiness view."""
    pp = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id))
    ta = await db.scalar(
        sa.select(TrustedAccessProfile).where(TrustedAccessProfile.website_id == website.id))
    av = await db.scalar(
        sa.select(AccessValidationResult).where(AccessValidationResult.website_id == website.id))
    conns = (await db.scalars(
        sa.select(ProviderConnection).where(
            ProviderConnection.website_id == website.id,
            ProviderConnection.connection_status == ProviderConnectionStatus.CONNECTED.value))).all()
    verified = website.verification_status == VerificationStatus.VERIFIED

    detected = detected_supported_providers(pp)
    connected = {c.provider for c in conns}

    checks: dict[str, ReadinessCheck] = {}
    checks["provider_discovery"] = _PASS if pp is not None else _FAIL
    checks["website_verified"] = _PASS if verified else _FAIL

    if ta is None:
        checks["trusted_access"] = _FAIL
    elif ta.access_status == TrustedAccessStatus.ACTIVE.value:
        checks["trusted_access"] = _PASS
    elif ta.access_status in (TrustedAccessStatus.PENDING.value, TrustedAccessStatus.LIMITED.value):
        checks["trusted_access"] = _WARN
    else:  # revoked / failed / not_configured
        checks["trusted_access"] = _FAIL

    # Completion gate: every DETECTED supported provider connected (not a scan).
    checks["provider_connected"] = provider_connected_check(detected, connected, verified=verified)

    # access_validation is a SOFT coverage/quality signal now — computed + returned,
    # but NOT in `checks` so it never blocks completion (no scan required to finish).
    if av is None:
        coverage = "pending"
    else:
        coverage = av.validation_status

    if not verified or checks["provider_connected"] is _FAIL:
        checks["monitoring_eligible"] = _FAIL
    elif checks["trusted_access"] is _WARN:
        checks["monitoring_eligible"] = _WARN
    else:
        checks["monitoring_eligible"] = _PASS

    if any(checks[c] is _FAIL for c in _HARD_CHECKS):
        status = OnboardingReadinessStatus.NOT_READY
    elif all(v is _PASS for v in checks.values()):
        status = OnboardingReadinessStatus.READY
    else:
        status = OnboardingReadinessStatus.LIMITED

    allowed = status is not OnboardingReadinessStatus.NOT_READY
    provider = _provider_label(ta, pp)

    evidence: list[str] = []
    if verified:
        evidence.append("ownership verified")
    else:
        evidence.append("ownership missing")
    if pp is not None:
        evidence.append(f"provider identified: {provider}")
    else:
        evidence.append("provider discovery incomplete")
    if ta is not None:
        evidence.append(f"trusted access {ta.access_status}")
    if av is not None:
        evidence.append(f"validation {av.validation_status}")
        if av.challenge_detected:
            evidence.append(f"challenge detected: {av.challenge_provider}")

    return {
        "status": status.value,
        "checks": {k: v.value for k, v in checks.items()},
        "monitoring_allowed": allowed,
        "deep_scan_allowed": allowed,
        "baseline_allowed": allowed,
        "provider": provider,
        "verification": website.verification_status.value,
        "trusted_access": ta.access_status if ta else "not_configured",
        # Soft coverage/quality signal — not a completion gate.
        "validation": coverage,
        "provider_connected": checks["provider_connected"].value,
        "providers": {
            "detected": sorted(detected),
            "connected": sorted(detected & connected),
            "missing": sorted(detected - connected),
        },
        "evidence": evidence,
    }


_RECOMMEND = {
    OnboardingReadinessStatus.READY.value: "Ready — monitoring and deep scans are enabled.",
    OnboardingReadinessStatus.LIMITED.value: "Monitoring may proceed, but visibility is restricted — complete trusted scanner access / re-validate to improve coverage.",
    OnboardingReadinessStatus.NOT_READY.value: "Onboarding incomplete — connect your detected provider(s) (or verify ownership) to finish.",
}


def dashboard_view(view: dict, *, monitoring_active: bool | None = None) -> dict:
    status = view["status"]
    out = dict(view)
    out["recommendation"] = _RECOMMEND.get(status, "")
    out["monitoring"] = (
        "blocked" if status == OnboardingReadinessStatus.NOT_READY.value
        else ("active" if monitoring_active else "enabled" if view["monitoring_allowed"] else "blocked")
    )
    out["coverage_notice"] = status == OnboardingReadinessStatus.LIMITED.value
    return out


async def _persist(db: AsyncSession, website: Website, view: dict) -> OnboardingReadiness:
    row = await db.scalar(
        sa.select(OnboardingReadiness).where(OnboardingReadiness.website_id == website.id))
    if row is None:
        row = OnboardingReadiness(website_id=website.id, domain=website.hostname)
        db.add(row)
    row.org_id = website.org_id
    row.domain = website.hostname
    row.status = view["status"]
    row.checks = view["checks"]
    row.monitoring_allowed = view["monitoring_allowed"]
    row.deep_scan_allowed = view["deep_scan_allowed"]
    row.baseline_allowed = view["baseline_allowed"]
    row.evidence = view["evidence"]
    row.evaluated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(row)
    return row


def _emit_decision_events(website: Website, view: dict) -> None:
    provider, status = view["provider"], view["status"]
    emit_onboarding_event(ONBOARDING_CHECK_COMPLETED, website, provider=provider, status=status)
    if status == OnboardingReadinessStatus.READY.value:
        emit_onboarding_event(ONBOARDING_READY, website, provider=provider, status=status)
    elif status == OnboardingReadinessStatus.LIMITED.value:
        emit_onboarding_event(ONBOARDING_LIMITED, website, provider=provider, status=status)
    else:
        emit_onboarding_event(ONBOARDING_BLOCKED, website, provider=provider, status=status)
    # Deep-scan activation decision (recorded; enforcement is a later
    # integration — this slice does not gate scan_jobs).
    emit_onboarding_event(
        DEEP_SCAN_ACTIVATION_ALLOWED if view["deep_scan_allowed"] else DEEP_SCAN_ACTIVATION_BLOCKED,
        website, provider=provider, status=status)


async def get_readiness_view(db: AsyncSession, website: Website) -> dict:
    """Read-only live readiness (no persist, no events) for the dashboard."""
    return dashboard_view(await evaluate(db, website))


async def activate_monitoring(
    db: AsyncSession, website: Website, *, user_id=None, org_id=None,
) -> dict:
    """Evaluate readiness, persist it, and — if readiness permits — enable
    monitoring (its schedule). Blocks (NotReadyError) when NOT_READY."""
    emit_onboarding_event(ONBOARDING_STARTED, website, status="evaluating")
    view = await evaluate(db, website)
    await _persist(db, website, view)
    _emit_decision_events(website, view)

    provider, status = view["provider"], view["status"]
    record_phase3_event(
        db, event_type=(DEEP_SCAN_ACTIVATION_ALLOWED if view["deep_scan_allowed"]
                        else DEEP_SCAN_ACTIVATION_BLOCKED),
        website=website, actor_user_id=user_id, org_id=org_id, provider=provider,
        status=status, resource_type="onboarding_readiness")
    if not view["monitoring_allowed"]:
        emit_onboarding_event(MONITORING_ACTIVATION_BLOCKED, website, provider=provider,
                              status=status, reason="not_ready")
        record_phase3_event(
            db, event_type=MONITORING_ACTIVATION_BLOCKED, website=website,
            actor_user_id=user_id, org_id=org_id, provider=provider, status=status,
            reason="not_ready", resource_type="onboarding_readiness")
        raise NotReadyError()

    # Enable (do not create) the website's monitoring schedule(s). Additive —
    # the auto-create-on-verify behaviour is untouched.
    await db.execute(
        sa.update(ScanSchedule).where(ScanSchedule.website_id == website.id)
        .values(is_enabled=True))
    emit_onboarding_event(MONITORING_ACTIVATION_ALLOWED, website, provider=provider,
                          status=status, reason=status)
    record_phase3_event(
        db, event_type=MONITORING_ACTIVATION_ALLOWED, website=website,
        actor_user_id=user_id, org_id=org_id, provider=provider, status=status,
        reason=status, resource_type="onboarding_readiness")
    return dashboard_view(view, monitoring_active=True)
