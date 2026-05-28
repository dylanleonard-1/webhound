# WebHound — apps/api/services/fraud.py
# Phase 5: Fraud & Abuse scoring and flag lifecycle.
#
# `evaluate_user` computes a score from independent signals (excessive scans,
# payment failures, IP/UA diversity, auth failures, high scan failure rate)
# and returns reason codes + supporting detail. The worker beat task feeds
# candidate user_ids into this and upserts a flag whenever the score crosses
# the threshold. Staff dismiss / escalate via /control/abuse.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.abuse import AbuseFlag, IPDeviceFingerprint
from apps.api.models.enums import ScanStatus, SubscriptionStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.subscription import Subscription
from apps.api.models.website import Website

logger = logging.getLogger(__name__)

# Reason → score weight. Tuning is conservative; only score >= FLAG_THRESHOLD
# generates a flag, so single weak signals stay silent.
_WEIGHTS: dict[str, int] = {
    "excessive_scans":   30,
    "failed_payments":   20,
    "auth_failures":     25,
    "many_ips":          15,
    "many_user_agents":  10,
    "high_fail_rate":    15,
}

FLAG_THRESHOLD = 30   # ignore lone weak signals

# Thresholds for each signal.
_SCANS_24H_HIGH      = 50
_DISTINCT_IPS_7D     = 5
_DISTINCT_UA_7D      = 4
_AUTH_FAIL_HIGH      = 5         # Redis auth:fail counter
_SCAN_FAIL_PCT       = 50.0
_SCAN_FAIL_MIN_RUNS  = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# --- Login fingerprinting ---------------------------------------------------


async def record_login_fingerprint(
    db: AsyncSession, *, user_id: uuid.UUID, ip_address: str | None,
    user_agent: str | None,
) -> None:
    """Upsert a (user, ip, ua) tuple — called on every successful login.

    Best-effort: never raises into the auth flow. We trim the user agent
    aggressively because the column is 500 chars wide and modern UA strings
    routinely exceed that.
    """
    if not ip_address:
        return
    ua = (user_agent or "")[:480]
    try:
        existing = await db.scalar(
            select(IPDeviceFingerprint).where(
                IPDeviceFingerprint.user_id == user_id,
                IPDeviceFingerprint.ip_address == ip_address,
                IPDeviceFingerprint.user_agent == ua,
            )
        )
        now = _now()
        if existing is None:
            db.add(IPDeviceFingerprint(
                user_id=user_id, ip_address=ip_address, user_agent=ua,
                first_seen_at=now, last_seen_at=now, occurrences=1,
            ))
        else:
            existing.occurrences += 1
            existing.last_seen_at = now
        await db.flush()
    except Exception:  # noqa: BLE001
        logger.debug("fingerprint record failed (non-fatal)", exc_info=True)


async def list_fingerprints(db: AsyncSession, user_id: uuid.UUID,
                            limit: int = 50) -> list[dict]:
    rows = await db.scalars(
        select(IPDeviceFingerprint)
        .where(IPDeviceFingerprint.user_id == user_id)
        .order_by(IPDeviceFingerprint.last_seen_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(f.id), "ip_address": f.ip_address, "user_agent": f.user_agent,
            "occurrences": f.occurrences,
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        }
        for f in rows.all()
    ]


# --- Signal evaluators (each returns matched? + detail dict) ---------------


async def _signal_excessive_scans(db: AsyncSession, user_id: uuid.UUID) -> tuple[bool, dict]:
    since = _now() - timedelta(hours=24)
    n = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id, ScanJob.created_at >= since)
    ) or 0
    return (n >= _SCANS_24H_HIGH, {"scans_24h": int(n), "threshold": _SCANS_24H_HIGH})


async def _signal_failed_payments(db: AsyncSession, user_id: uuid.UUID) -> tuple[bool, dict]:
    n = await db.scalar(
        select(func.count()).select_from(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_((SubscriptionStatus.PAST_DUE,
                                     SubscriptionStatus.UNPAID,
                                     SubscriptionStatus.INCOMPLETE_EXPIRED)),
        )
    ) or 0
    return (n > 0, {"problem_subscriptions": int(n)})


async def _signal_high_fail_rate(db: AsyncSession, user_id: uuid.UUID) -> tuple[bool, dict]:
    since = _now() - timedelta(days=7)
    total = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id, ScanJob.created_at >= since)
    ) or 0
    failed = await db.scalar(
        select(func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == user_id, ScanJob.created_at >= since,
               ScanJob.status == ScanStatus.FAILED)
    ) or 0
    total, failed = int(total), int(failed)
    if total < _SCAN_FAIL_MIN_RUNS:
        return (False, {"runs_7d": total, "fail_pct": 0})
    pct = round(100 * failed / total, 1)
    return (pct >= _SCAN_FAIL_PCT, {"runs_7d": total, "failed_7d": failed, "fail_pct": pct})


async def _signal_ip_ua_diversity(db: AsyncSession, user_id: uuid.UUID) -> tuple[bool, dict, bool, dict]:
    since = _now() - timedelta(days=7)
    ips = await db.scalar(
        select(func.count(func.distinct(IPDeviceFingerprint.ip_address)))
        .where(IPDeviceFingerprint.user_id == user_id,
               IPDeviceFingerprint.last_seen_at >= since)
    ) or 0
    uas = await db.scalar(
        select(func.count(func.distinct(IPDeviceFingerprint.user_agent)))
        .where(IPDeviceFingerprint.user_id == user_id,
               IPDeviceFingerprint.last_seen_at >= since)
    ) or 0
    ips, uas = int(ips), int(uas)
    return (
        ips >= _DISTINCT_IPS_7D, {"distinct_ips_7d": ips, "threshold": _DISTINCT_IPS_7D},
        uas >= _DISTINCT_UA_7D, {"distinct_uas_7d": uas, "threshold": _DISTINCT_UA_7D},
    )


async def _signal_auth_failures(email: str) -> tuple[bool, dict]:
    """Reads the Redis counter our rate limiter increments on bad passwords."""
    if not email:
        return False, {}
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1,
                              decode_responses=True)
        try:
            raw = await r.get(f"auth:fail:{email.lower()}")
            count = int(raw) if raw else 0
            locked = bool(await r.exists(f"auth:lock:{email.lower()}"))
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        return False, {}
    matched = locked or count >= _AUTH_FAIL_HIGH
    return matched, {"failures": count, "locked": locked, "threshold": _AUTH_FAIL_HIGH}


async def evaluate_user(db: AsyncSession, user_id: uuid.UUID,
                        email: str | None = None) -> dict:
    """Compute the abuse score for one user. Returns
    {score, severity, reasons[], detail{}}; the caller decides whether to
    upsert a flag based on FLAG_THRESHOLD."""
    reasons: list[str] = []
    detail: dict[str, dict] = {}

    matched, d = await _signal_excessive_scans(db, user_id)
    detail["excessive_scans"] = d
    if matched:
        reasons.append("excessive_scans")

    matched, d = await _signal_failed_payments(db, user_id)
    detail["failed_payments"] = d
    if matched:
        reasons.append("failed_payments")

    matched, d = await _signal_high_fail_rate(db, user_id)
    detail["high_fail_rate"] = d
    if matched:
        reasons.append("high_fail_rate")

    ips_matched, ips_d, uas_matched, uas_d = await _signal_ip_ua_diversity(db, user_id)
    detail["many_ips"] = ips_d
    detail["many_user_agents"] = uas_d
    if ips_matched:
        reasons.append("many_ips")
    if uas_matched:
        reasons.append("many_user_agents")

    if email:
        matched, d = await _signal_auth_failures(email)
        detail["auth_failures"] = d
        if matched:
            reasons.append("auth_failures")

    score = sum(_WEIGHTS.get(r, 0) for r in reasons)
    return {"score": score, "severity": _severity(score),
            "reasons": reasons, "detail": detail}


# --- Flag lifecycle ---------------------------------------------------------


async def upsert_flag(
    db: AsyncSession, *,
    user_id: uuid.UUID | None, ip_address: str | None,
    score: int, severity: str, reasons: list[str], detail: dict,
) -> tuple[AbuseFlag, bool]:
    """Upsert by dedup_key (`user:<id>` or `ip:<ip>`); bumps occurrences when
    the same signal fires again, re-opens if the flag was resolved earlier."""
    dedup_key = f"user:{user_id}" if user_id else f"ip:{ip_address}"
    existing = await db.scalar(select(AbuseFlag).where(AbuseFlag.dedup_key == dedup_key))
    now = _now()
    if existing is None:
        flag = AbuseFlag(
            dedup_key=dedup_key, user_id=user_id, ip_address=ip_address,
            score=score, severity=severity, status="pending",
            reasons=list(reasons), detail=dict(detail), occurrences=1,
            first_seen_at=now, last_seen_at=now,
        )
        db.add(flag)
        await db.flush()
        return flag, True

    existing.occurrences += 1
    existing.last_seen_at = now
    existing.score = score
    existing.severity = severity
    existing.reasons = list(reasons)
    existing.detail = dict(detail)
    if existing.status == "dismissed":
        existing.status = "pending"
        existing.resolved_at = None
        existing.resolved_by_email = None
    await db.flush()
    return existing, False


async def auto_resolve_if_cleared(db: AsyncSession, flag: AbuseFlag,
                                  *, new_score: int) -> bool:
    """Close a pending flag whose signals have cleared (score under threshold)."""
    if flag.status != "pending" or new_score >= FLAG_THRESHOLD:
        return False
    flag.status = "dismissed"
    flag.resolved_at = _now()
    flag.resolved_by_email = "system"
    flag.resolution_note = "Signals cleared on re-evaluation."
    await db.flush()
    return True


async def dismiss(db: AsyncSession, flag: AbuseFlag, *,
                  actor_email: str | None, note: str | None) -> AbuseFlag:
    flag.status = "dismissed"
    flag.resolved_at = _now()
    flag.resolved_by_email = actor_email
    flag.resolution_note = note
    await db.flush()
    return flag


async def mark_banned(db: AsyncSession, flag: AbuseFlag, *,
                      actor_email: str | None) -> AbuseFlag:
    """Move the flag into `banned` status. The caller is responsible for
    actually suspending the user via the customer service (so the audit row
    lands under customer.suspend, not here)."""
    flag.status = "banned"
    flag.resolved_at = _now()
    flag.resolved_by_email = actor_email
    flag.resolution_note = "Escalated to account suspension."
    await db.flush()
    return flag


# --- Candidate user selection (used by the worker evaluator) ----------------


async def find_candidates(db: AsyncSession) -> list[uuid.UUID]:
    """Return user_ids worth evaluating right now.

    Cheap aggregate queries pick anyone hitting any high-volume signal so we
    don't evaluate every user on every tick.
    """
    since_24h = _now() - timedelta(hours=24)
    since_7d = _now() - timedelta(days=7)
    ids: set[uuid.UUID] = set()

    # High scan volume in 24h.
    rows = await db.execute(
        select(Website.user_id, func.count().label("n"))
        .join(ScanJob, ScanJob.website_id == Website.id)
        .where(ScanJob.created_at >= since_24h, Website.user_id.is_not(None))
        .group_by(Website.user_id)
        .having(func.count() >= _SCANS_24H_HIGH)
    )
    ids.update(uid for uid, _ in rows.all())

    # Payment problems.
    rows = await db.scalars(
        select(Subscription.user_id).where(
            Subscription.status.in_((SubscriptionStatus.PAST_DUE,
                                     SubscriptionStatus.UNPAID,
                                     SubscriptionStatus.INCOMPLETE_EXPIRED)),
        )
    )
    ids.update(rows.all())

    # IP / UA diversity.
    rows = await db.execute(
        select(
            IPDeviceFingerprint.user_id,
            func.count(func.distinct(IPDeviceFingerprint.ip_address)).label("ips"),
            func.count(func.distinct(IPDeviceFingerprint.user_agent)).label("uas"),
        )
        .where(IPDeviceFingerprint.last_seen_at >= since_7d)
        .group_by(IPDeviceFingerprint.user_id)
        .having(sa.or_(
            func.count(func.distinct(IPDeviceFingerprint.ip_address)) >= _DISTINCT_IPS_7D,
            func.count(func.distinct(IPDeviceFingerprint.user_agent)) >= _DISTINCT_UA_7D,
        ))
    )
    ids.update(uid for uid, _ips, _uas in rows.all())

    return list(ids)
