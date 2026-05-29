# WebHound — apps/api/services/public_scan.py
# Slice 4.A — Public/guest scan flow.
#
# A visitor enters a URL on /scan with no account. We reuse the
# production scan pipeline (Website + ScanJob + Celery worker) with
# two adjustments:
#
#   * Website row gets ``user_id=None`` (admin-imported pattern —
#     already supported by the model).
#   * ScanJob row gets ``guest_token`` set; the public router only
#     accepts lookups by token so a guest can't enumerate other
#     scans.
#
# Hard rule (architecture): NO PARALLEL SCAN SYSTEM. Same Website
# table, same ScanJob table, same Celery task. The only "new"
# code is the entry point + a per-IP rate limit + the token.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import (
    ScanProfile,
    ScanStatus,
    VerificationStatus,
)
from apps.api.models.scan_job import ScanJob
from apps.api.models.website import Website
from apps.api.rate_limit import RateDecision, check_rate

logger = logging.getLogger(__name__)


# H4 — guest scans use the QUICK profile (~30s wall clock) so the
# first-time visitor sees a finished report in the same session
# they entered the URL. A logged-in user can re-run with the
# DEEP/STANDARD profile after they save the report.
_GUEST_PROFILE = ScanProfile.QUICK

# G4 — IP rate limit. 3 scans / IP / day. Existing
# ``check_rate`` is a Redis-backed sliding window.
_IP_LIMIT = 3
_IP_WINDOW_SECONDS = 24 * 60 * 60      # 24 hours


class PublicScanError(ValueError):
    """Public-flow validation errors that should surface to the
    caller as 4xx (not 5xx). The router converts these into
    HTTPException with a clear plain-English detail."""


# ---------------------------------------------------------------------------
# URL validation — bare minimum so the worker doesn't burn cycles
# on malformed input. Live deeper validation happens inside the
# scanner core (target_validation module).
# ---------------------------------------------------------------------------


def _normalise_url(raw: str) -> str:
    """Accept ``acme-cafe.com`` / ``www.acme-cafe.com`` /
    ``https://acme-cafe.com`` and return a canonical ``https://...``
    URL the scanner accepts."""
    candidate = (raw or "").strip()
    if not candidate:
        raise PublicScanError("Enter a website URL.")
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
    except Exception:  # noqa: BLE001
        raise PublicScanError("That doesn’t look like a valid website URL.")
    if parsed.scheme not in ("http", "https"):
        raise PublicScanError("Only http and https URLs can be scanned.")
    host = (parsed.hostname or "").strip().lower()
    if not host or "." not in host:
        raise PublicScanError("Enter a website URL like example.com.")
    # Block IPs / private hosts — the public flow is for real
    # websites, not internal endpoints. The scanner's own
    # target_validation module enforces this strictly; this is
    # the early-fail copy for the visitor.
    if host in ("localhost", "127.0.0.1", "::1"):
        raise PublicScanError("Local addresses can’t be scanned here.")
    return f"{parsed.scheme}://{host}{parsed.path or ''}".rstrip("/")


def _hostname_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


# ---------------------------------------------------------------------------
# Entry point — create the guest Website + ScanJob and enqueue.
# ---------------------------------------------------------------------------


async def check_ip_rate_limit(client_ip: str) -> RateDecision:
    """Returns the rate-limit decision for this IP. Caller (router)
    converts a denied decision into a 429 with a clear retry-after
    message."""
    key = f"pubscan:ip:{client_ip}:day"
    return await check_rate(
        key, limit=_IP_LIMIT, window_seconds=_IP_WINDOW_SECONDS,
    )


async def create_guest_scan(
    db: AsyncSession,
    *,
    raw_url: str,
    client_ip: str,
) -> dict[str, Any]:
    """Create a guest scan job. Returns a payload the public
    router serialises directly to the response body.

    Order of operations matters:
      1. Validate + normalise URL (cheap, fail fast).
      2. Check IP rate limit (cheap, fail fast).
      3. Create Website (user_id=None, verification_status=UNVERIFIED).
      4. Create ScanJob with guest_token + QUICK profile.
      5. Enqueue the Celery task (same task authenticated scans
         use — no parallel pipeline).

    Each step is independently reversible; the public flow never
    leaves an orphaned Website with no scan attached.
    """
    url = _normalise_url(raw_url)

    # Rate-limit check. The router calls this separately too — both
    # call sites are protected. Done here so service-direct callers
    # (tests, admin tooling) also respect the limit.
    decision = await check_ip_rate_limit(client_ip)
    if not decision.allowed:
        raise PublicScanError(
            f"You’ve started {_IP_LIMIT} scans in the last 24 hours. "
            "Try again later — or create an account to keep scanning.",
        )

    host = _hostname_from_url(url)
    parsed = urlparse(url)
    scheme = parsed.scheme

    website = Website(
        # No user_id — admin-imported / guest pattern. This is
        # already an allowed state per the Website model.
        user_id=None,
        org_id=None,
        url=url,
        hostname=host,
        scheme=scheme,
        # Verification gate doesn't apply to guest scans — they
        # never persist beyond the 24h window unless the visitor
        # claims the scan via /save-report (slice 4.C).
        verification_status=VerificationStatus.UNVERIFIED,
    )
    db.add(website)
    await db.flush()

    guest_token = uuid.uuid4()
    job = ScanJob(
        website_id=website.id,
        profile=_GUEST_PROFILE,
        requested_url=url,
        status=ScanStatus.QUEUED,
        guest_token=guest_token,
        # Don't save baselines for guests — they don't have a
        # persistent account to attach the baseline to.
        save_baseline=False,
        use_latest_baseline=False,
    )
    db.add(job)
    await db.flush()

    # Enqueue the existing production worker task. NO new worker,
    # NO new queue.
    try:
        from worker.scan_tasks import run_scan
        task = run_scan.delay(str(job.id), url, _GUEST_PROFILE.value)
        job.celery_task_id = task.id
    except Exception:  # noqa: BLE001
        logger.exception("failed to enqueue guest scan task")
        # We still return the scan record — the dispatcher will
        # retry via the monitoring beat. Don't leak the broker
        # error to the visitor.

    await db.commit()
    return {
        "scan_id": str(job.id),
        "guest_token": str(guest_token),
        "status": ScanStatus.QUEUED.value,
        "target_url": url,
        "started_at": None,
        "completed_at": None,
        "profile": _GUEST_PROFILE.value,
        "rate_limit_remaining": decision.remaining,
    }


# ---------------------------------------------------------------------------
# Status lookup — token-scoped (never id-scoped).
# ---------------------------------------------------------------------------


async def get_guest_scan_status(
    db: AsyncSession, guest_token: uuid.UUID,
) -> dict[str, Any] | None:
    """Look up a guest scan by token. Returns ``None`` when the
    token isn't recognised so the router can render a 404 without
    leaking whether a token ever existed."""
    row = await db.scalar(
        sa.select(ScanJob).where(ScanJob.guest_token == guest_token),
    )
    if row is None:
        return None

    # Eager-load the related scan result for the summary view, but
    # tolerate its absence (the scan may still be running).
    result_summary: dict[str, Any] | None = None
    if row.status == ScanStatus.COMPLETED:
        from apps.api.models.scan_result import ScanResultRecord
        result = await db.scalar(
            sa.select(ScanResultRecord).where(
                ScanResultRecord.scan_job_id == row.id,
            ),
        )
        if result is not None:
            result_summary = {
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "total_findings": result.total_findings,
                "actionable_findings": result.actionable_findings,
                "severity_breakdown": result.severity_breakdown,
                "duration_seconds": result.duration_seconds,
            }

    return {
        "scan_id": str(row.id),
        "guest_token": str(row.guest_token),
        "status": row.status.value,
        "target_url": row.requested_url,
        "profile": row.profile.value,
        "started_at": _iso(row.started_at),
        "completed_at": _iso(row.completed_at),
        "error_message": row.error_message,
        "result": result_summary,
    }


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
