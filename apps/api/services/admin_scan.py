# WebHound — apps/api/services/admin_scan.py
# Internal/admin-only on-demand scan runner. Lets authorized devs/ops run
# ANY scan profile (quick/standard/deep/enterprise/monitor/baseline) through
# the EXISTING production pipeline — same Website + ScanJob + Celery worker +
# persistence + telemetry. There is deliberately NO parallel scanner path and
# NO change to scanner behaviour: this module only creates a job and enqueues
# the production task, then reads back the persisted telemetry.
#
# Security posture (see hard rules in the design brief):
#   * NOT public. Callers are the internal API (require_admin) or the admin
#     CLI (shell/deploy access to the worker env). Both go through here.
#   * Every run is audit-logged (who/url/profile/reason/job_id/timestamp).
#   * Domain ownership / allowlist is enforced UNLESS internal_test_mode is
#     explicitly set (which is itself audited).
#   * Never weakens scanner safe-scanning controls — those live in the
#     scanner core and are untouched.

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import ScanProfile, ScanStatus, VerificationStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website
from apps.api.schemas.scan_jobs import ScanJobCreate
from apps.api.services import scan_jobs as sj_service
from apps.api.services.public_scan import _normalise_url

logger = logging.getLogger(__name__)

# Profiles an admin may request. "baseline" is an alias — there is no
# BASELINE ScanProfile; it runs DEEP and persists a fresh WADE baseline.
_REAL_PROFILES = {"quick", "standard", "deep", "monitor", "enterprise"}
ALLOWED_PROFILES = sorted(_REAL_PROFILES | {"baseline"})

# Profiles whose ScanProfile actually wants the browser pass — used only to
# annotate the telemetry read (observability), never to gate behaviour.
_BROWSER_PROFILES = {"standard", "deep", "enterprise"}

_DEFAULT_ALLOWLIST = "webhoundsecurity.com,webhound.io"


class AdminScanError(ValueError):
    """Caller-facing validation error (4xx for the API, exit-2 for the CLI)."""


def _resolve_profile(profile: str) -> tuple[ScanProfile, bool]:
    """Return (ScanProfile, save_baseline_default). 'baseline' → DEEP+save."""
    p = (profile or "").strip().lower()
    if p == "baseline":
        return ScanProfile.DEEP, True
    if p in _REAL_PROFILES:
        return ScanProfile(p), False
    raise AdminScanError(
        f"unknown profile '{profile}'. Allowed: {', '.join(ALLOWED_PROFILES)}")


def _allowlist() -> set[str]:
    raw = os.getenv("WEBHOUND_INTERNAL_SCAN_ALLOWLIST", _DEFAULT_ALLOWLIST)
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _host_allowlisted(host: str) -> bool:
    allow = _allowlist()
    return host in allow or any(host == d or host.endswith("." + d) for d in allow)


async def _find_owned_website(db: AsyncSession, host: str) -> Website | None:
    """An existing OWNED website (user_id set) for this host means a real
    customer owns/verified the domain — scanning it is allowed."""
    return await db.scalar(
        sa.select(Website)
        .where(Website.hostname == host, Website.user_id.isnot(None))
        .limit(1)
    )


async def run_admin_scan(
    db: AsyncSession,
    *,
    url: str,
    profile: str,
    reason: str,
    triggered_by: str,
    actor: Any = None,
    internal_test_mode: bool = False,
    save_baseline: bool | None = None,
    use_latest_baseline: bool = False,
    audit_ctx: dict | None = None,
) -> dict[str, Any]:
    """Create + enqueue an admin scan on the production pipeline.

    Returns {job_id, scan_id, profile, status, url}. ``scan_id`` is the
    job id (the identifier every API/DB lookup keys on); the scanner's
    internal result id is surfaced later by ``read_scan_telemetry``.
    """
    if not (reason or "").strip():
        raise AdminScanError("reason is required for an admin scan (audit).")
    if not (triggered_by or "").strip():
        raise AdminScanError("triggered_by is required (audit).")

    norm = _normalise_url(url)  # raises PublicScanError on bad input
    parsed = urlparse(norm)
    host = (parsed.hostname or "").lower()
    scan_profile, baseline_default = _resolve_profile(profile)
    if save_baseline is None:
        save_baseline = baseline_default

    # --- Ownership / allowlist gate (skipped only in internal test mode) ---
    owned = await _find_owned_website(db, host)
    if not internal_test_mode and owned is None and not _host_allowlisted(host):
        raise AdminScanError(
            f"'{host}' is not an owned/verified website and not on the "
            "internal allowlist (WEBHOUND_INTERNAL_SCAN_ALLOWLIST). Re-run "
            "with internal_test_mode to override (audited).")

    # Reuse an owned site when present (respects tenancy); otherwise create an
    # unowned internal Website (user_id/org_id None — the existing
    # admin-imported/guest pattern, allowed by the model).
    website = owned
    if website is None:
        website = await db.scalar(
            sa.select(Website).where(Website.url == norm).limit(1))
    if website is None:
        website = Website(
            user_id=None, org_id=None, url=norm, hostname=host,
            scheme=parsed.scheme,
            verification_status=VerificationStatus.UNVERIFIED)
        db.add(website)
        await db.flush()

    # Same production job-creation path admins use for force-rescan. is_admin
    # bypasses the owner verification gate (we enforce our own gate above);
    # it NEVER changes how the scanner runs.
    job = await sj_service.create_scan_job(
        db,
        ScanJobCreate(
            website_id=website.id, profile=scan_profile,
            use_latest_baseline=use_latest_baseline,
            save_baseline=bool(save_baseline)),
        is_admin=True)

    enqueued = False
    try:
        from worker.scan_tasks import run_scan
        task = run_scan.delay(str(job.id), website.url, scan_profile.value)
        job.celery_task_id = task.id
        enqueued = True
    except Exception:  # noqa: BLE001 — broker hiccup shouldn't lose the job
        logger.exception("failed to enqueue admin scan for job %s", job.id)

    # Audit trail — always logged; the API path also writes an immutable
    # admin_audit_log row via record_action (actor supplied).
    audit_detail = {
        "url": website.url, "profile": scan_profile.value,
        "reason": reason, "triggered_by": triggered_by,
        "internal_test_mode": internal_test_mode,
        "save_baseline": bool(save_baseline), "enqueued": enqueued,
        "job_id": str(job.id),
    }
    logger.warning(
        "ADMIN_SCAN triggered_by=%s reason=%r url=%s profile=%s job_id=%s "
        "scan_id=%s internal_test_mode=%s ts=%s",
        triggered_by, reason, website.url, scan_profile.value, job.id, job.id,
        internal_test_mode, datetime.now(timezone.utc).isoformat())
    if actor is not None:
        try:
            from apps.api.internal.audit import record_action
            await record_action(
                db, actor=actor, action="scan.admin_run",
                target_type="scan_job", target_id=str(job.id),
                detail=audit_detail, **(audit_ctx or {}))
        except Exception:  # noqa: BLE001 — audit fan-out must not fail the run
            logger.exception("admin scan audit record failed (job %s)", job.id)

    return {
        "job_id": str(job.id),
        "scan_id": str(job.id),
        "profile": scan_profile.value,
        "status": ScanStatus.QUEUED.value,
        "url": website.url,
    }


def _browser_enabled_for(profile_name: str) -> bool | None:
    """Authoritative browser_enabled for a profile (read-only). Prefers the
    scanner's own profile registry; falls back to the known set."""
    try:
        from webhound.core.scan_profiles import get_profile
        return bool(get_profile(profile_name).to_scan_options().browser_enabled)
    except Exception:  # noqa: BLE001
        return profile_name in _BROWSER_PROFILES


async def read_scan_telemetry(
    db: AsyncSession, job_id: uuid.UUID | str,
) -> dict[str, Any]:
    """Read the persisted telemetry + browser_pass for an admin scan job and
    fold it into a verification view that directly answers the browser-
    telemetry checklist. Pure read — no scanner involvement."""
    jid = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    job = await db.get(ScanJob, jid)
    if job is None:
        raise AdminScanError(f"scan job not found: {job_id}")

    profile = job.profile.value if hasattr(job.profile, "value") else str(job.profile)
    result = await db.scalar(
        sa.select(ScanResultRecord)
        .where(ScanResultRecord.scan_job_id == jid)
        .order_by(ScanResultRecord.created_at.desc()))

    out: dict[str, Any] = {
        "job_id": str(jid),
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "profile": profile,
        "url": job.requested_url,
        "browser_enabled_expected": _browser_enabled_for(profile),
        "result_persisted": result is not None,
    }
    if result is None:
        return out

    md = result.scanner_metadata or {}
    tel = md.get("telemetry") or {}
    counts = tel.get("event_type_counts") or {}
    handoffs = tel.get("handoffs") or {}
    bp = md.get("browser_pass")
    abd = handoffs.get("after_browser_discovery")

    out.update({
        "scanner_scan_id": result.scan_id,
        "pages_crawled": result.pages_crawled,
        "duration_seconds": result.duration_seconds,
        "telemetry_present": bool(tel),
        "telemetry_level": tel.get("level"),
        "event_type_counts": counts,
        # Browser-telemetry checklist signals.
        "checks": {
            "telemetry_present": bool(tel),
            "profile_loaded_fired": counts.get("profile.loaded", 0) >= 1,
            "profile_is": profile,
            "browser_enabled_expected": _browser_enabled_for(profile),
            "browser_started_fired": counts.get("browser.started", 0) >= 1,
            "browser_finished_fired": counts.get("browser.finished", 0) >= 1,
            "browser_deferred_fired": counts.get("browser.deferred", 0) >= 1,
            "after_browser_discovery_present": abd is not None,
        },
        "after_browser_discovery": abd,
        "browser_pass": bp,
    })
    # Cross-check: telemetry handoff vs the browser_pass metadata block.
    if abd is not None and isinstance(bp, dict):
        out["browser_pass_agrees"] = (
            abd.get("rendered_link_count") == bp.get("rendered_links_found")
            and bool(abd.get("deferred")) == bool(bp.get("deferred")))
    # Coverage comparison (the deep≈standard question).
    rl = (bp or {}).get("rendered_links_found")
    out["coverage"] = {
        "pages_crawled": result.pages_crawled,
        "rendered_links_found": rl,
        "rendered_pages": (bp or {}).get("browser_pages_rendered"),
        "artifact_count": (bp or {}).get("artifact_count"),
        "browser_deferred": (bp or {}).get("deferred"),
    }
    return out
