# WebHound — apps/api/services/monitoring.py
# Phase-4 continuous monitoring: scan-completion hook that computes the
# delta against the prior scan of the same website and (when drift is
# significant enough) raises an alert.
#
# This is the connective tissue between:
#   * scanner/orchestrator output (ScanResultRecord.scanner_metadata)
#   * services/scan_delta.compute_delta (pure-function diff)
#   * services/alerts.upsert_alert (deduplicated alert lifecycle)
#
# Best-effort by design — a failure here MUST NOT mark the scan as
# failed. The scan completed; the monitoring layer is additive
# intelligence on top.

from __future__ import annotations

import logging
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import DriftSeverity, ScanStatus
from apps.api.models.scan_delta import ScanDelta
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.services.scan_delta import (
    ScanFingerprint,
    compute_delta,
    persist_delta,
)

logger = logging.getLogger(__name__)


# Map our drift severity onto the alert-engine string severity. LOW and
# NONE don't dispatch alerts — they're only visible in the dashboard
# drift feed, by design (alert-fatigue avoidance, Phase 4 §6B).
_DRIFT_TO_ALERT_SEVERITY = {
    DriftSeverity.MEDIUM: "medium",
    DriftSeverity.HIGH: "high",
    DriftSeverity.CRITICAL: "critical",
}


async def handle_scan_completion(
    db: AsyncSession,
    *,
    scan_job_id: uuid.UUID,
    website_id: uuid.UUID,
) -> ScanDelta | None:
    """Run the post-completion monitoring pass for one scan.

    Resolves the current ``ScanResultRecord`` + the most recent prior
    completed scan for the same website, builds ScanFingerprints, calls
    :func:`compute_delta`, persists the result, and dispatches a
    drift-alert when severity ≥ MEDIUM.

    Returns the persisted :class:`ScanDelta` (even the first-ever-scan
    NONE baseline row), or ``None`` if no current result exists yet —
    e.g. the scan failed mid-flight before a result was written. Never
    raises — callers can ignore the return value safely."""
    try:
        current_job, current_result = await _load_scan(db, scan_job_id)
        if current_result is None:
            return None

        previous_job, previous_result = await _load_previous_scan(
            db, website_id=website_id, exclude_scan_job_id=scan_job_id,
        )
        current_fp = ScanFingerprint.from_scan_result(
            current_result, scan_job=current_job,
        )
        previous_fp = (
            ScanFingerprint.from_scan_result(
                previous_result, scan_job=previous_job,
            ) if previous_result is not None else None
        )

        computed = compute_delta(current_fp, previous_fp)
        delta = await persist_delta(db, computed)

        # Only dispatch alerts for material drift — LOW + NONE land in the
        # dashboard drift feed but don't page anyone.
        if delta.drift_severity in _DRIFT_TO_ALERT_SEVERITY:
            await _dispatch_drift_alert(
                db, website_id=website_id, scan_job_id=scan_job_id,
                delta=delta,
            )
        return delta
    except Exception:  # noqa: BLE001
        logger.warning(
            "monitoring.handle_scan_completion failed for job %s — "
            "non-fatal, scan stays completed",
            scan_job_id, exc_info=True,
        )
        return None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _load_scan(
    db: AsyncSession, scan_job_id: uuid.UUID,
) -> tuple[ScanJob | None, ScanResultRecord | None]:
    job = await db.scalar(
        sa.select(ScanJob).where(ScanJob.id == scan_job_id),
    )
    result = await db.scalar(
        sa.select(ScanResultRecord).where(
            ScanResultRecord.scan_job_id == scan_job_id,
        ),
    )
    return job, result


async def _load_previous_scan(
    db: AsyncSession,
    *,
    website_id: uuid.UUID,
    exclude_scan_job_id: uuid.UUID,
) -> tuple[ScanJob | None, ScanResultRecord | None]:
    """Most recent ``COMPLETED`` scan for the website, excluding the
    current one. Returns ``(None, None)`` when there isn't one — i.e.
    this is the first scan for the target."""
    prev_job = await db.scalar(
        sa.select(ScanJob)
        .where(
            ScanJob.website_id == website_id,
            ScanJob.id != exclude_scan_job_id,
            ScanJob.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanJob.completed_at.desc().nulls_last(),
                   ScanJob.created_at.desc())
        .limit(1),
    )
    if prev_job is None:
        return None, None
    prev_result = await db.scalar(
        sa.select(ScanResultRecord).where(
            ScanResultRecord.scan_job_id == prev_job.id,
        ),
    )
    return prev_job, prev_result


async def _dispatch_drift_alert(
    db: AsyncSession,
    *,
    website_id: uuid.UUID,
    scan_job_id: uuid.UUID,
    delta: ScanDelta,
) -> None:
    """Raise a deduplicated drift alert for the given scan delta.

    ``dedup_key`` is per-website so repeated drift on the same site is
    one rising-occurrence-count alert rather than a new alert per scan
    — avoids the "every Monday morning a wall of identical alerts"
    failure mode. Severity is updated on each re-emit so a site that
    stays in HIGH drift but crosses into CRITICAL gets the upgrade."""
    from apps.api.services import alerts as alert_svc

    severity = _DRIFT_TO_ALERT_SEVERITY[delta.drift_severity]
    summary = delta.drift_summary or "Scan-to-scan drift detected."
    dedup_key = f"monitoring:drift:{website_id}"
    title = f"Scan drift detected ({delta.drift_severity.value})"
    description = (
        f"Continuous-monitoring delta vs prior scan flagged "
        f"{delta.drift_severity.value} drift: {summary}"
    )
    detail = {
        "website_id": str(website_id),
        "scan_job_id": str(scan_job_id),
        "delta_id": str(delta.id),
        "drift_severity": delta.drift_severity.value,
        "risk_score_delta": delta.risk_score_delta,
        "new_domain_count": len(delta.new_domains or []),
        "removed_domain_count": len(delta.removed_domains or []),
        "changed_header_count": len(delta.changed_headers or []),
        "changed_tls": bool(delta.changed_tls),
        "new_form_count": len(delta.new_forms or []),
        "new_api_count": len(delta.new_apis or []),
    }
    await alert_svc.upsert_alert(
        db,
        dedup_key=dedup_key,
        source="monitoring",
        severity=severity,
        title=title,
        description=description,
        target_type="website",
        target_id=str(website_id),
        detail=detail,
    )
