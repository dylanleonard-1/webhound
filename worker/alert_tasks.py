from __future__ import annotations

import asyncio
import logging

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)

# Thresholds — tuned to surface real operational problems without noise.
_FAILED_SCAN_WINDOW_MIN = 30      # alert on scans that failed in the last N min
_ENGINE_WINDOW_DAYS = 7           # reliability window
_ENGINE_MIN_RUNS = 5              # ignore engines with too little data
_ENGINE_FAIL_PCT = 50.0          # failure rate that warrants an alert
_QUEUE_WARN = 50                  # queue depth → medium
_QUEUE_CRIT = 200                 # queue depth → high
_WORKER_STALE_S = 900             # heartbeat older than this → worker down


@celery.task(name="worker.alert_tasks.evaluate_alerts")
def evaluate_alerts() -> dict:
    """Derive SOC alerts from current system state. Fires every 5 min via beat."""
    try:
        return asyncio.run(_evaluate())
    except Exception:
        logger.exception("evaluate_alerts failed")
        raise


async def _evaluate() -> dict:
    from datetime import datetime, timedelta, timezone

    import apps.api.models  # noqa: F401 — register models
    from sqlalchemy import func, select
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from apps.api.models.alert import Alert
    from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.website import Website
    from apps.api.services import alerts as alert_svc

    now = datetime.now(timezone.utc)
    counts = {"opened": 0, "updated": 0, "resolved": 0, "auto_disabled": 0}

    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            # 1) Recently failed scans — one alert per job (point-in-time).
            since = now - timedelta(minutes=_FAILED_SCAN_WINDOW_MIN)
            rows = await db.execute(
                select(ScanJob, Website.hostname)
                .join(Website, ScanJob.website_id == Website.id)
                .where(ScanJob.status == "failed", ScanJob.completed_at >= since)
            )
            for job, hostname in rows.all():
                _, created = await alert_svc.upsert_alert(
                    db,
                    dedup_key=f"scan_failure:{job.id}",
                    source="scan_failure",
                    severity="high",
                    title=f"Scan failed: {hostname or job.requested_url}",
                    description=(job.error_message or "Scan job ended in failed state."),
                    target_type="scan_job", target_id=str(job.id),
                    detail={"profile": getattr(job.profile, "value", str(job.profile)),
                            "url": job.requested_url},
                )
                counts["opened" if created else "updated"] += 1

            # 2) Engine reliability degradation (rolling window).
            ewin = now - timedelta(days=_ENGINE_WINDOW_DAYS)
            erows = await db.execute(
                select(
                    EngineDiagnosticRecord.engine_name,
                    func.count().label("runs"),
                    func.sum(sa.case((EngineDiagnosticRecord.status == "failed", 1), else_=0)).label("failed"),
                )
                .where(EngineDiagnosticRecord.created_at >= ewin)
                .group_by(EngineDiagnosticRecord.engine_name)
            )
            degraded: set[str] = set()
            from apps.api.models.engine import EngineRegistry
            reg_rows = await db.scalars(select(EngineRegistry))
            registry_by_name: dict[str, EngineRegistry] = {r.name: r for r in reg_rows.all()}
            auto_disabled_this_tick: list[str] = []

            for name, runs, failed in erows.all():
                runs = int(runs or 0)
                failed = int(failed or 0)
                if runs < _ENGINE_MIN_RUNS:
                    continue
                fail_pct = round(100 * failed / runs, 1)
                # Phase 11: auto-disable enforcement. If the registry has a
                # threshold and we're past it, flip the engine into
                # maintenance + stamp auto_disabled_at. The alert gets bumped
                # to critical for the SOC.
                reg = registry_by_name.get(name)
                hit_auto = (reg is not None
                            and reg.auto_disable_at_failure_pct is not None
                            and fail_pct >= reg.auto_disable_at_failure_pct
                            and not reg.maintenance_mode)
                if hit_auto:
                    reg.maintenance_mode = True
                    reg.auto_disabled_at = now
                    reg.updated_by_email = "system"
                    auto_disabled_this_tick.append(name)

                if fail_pct >= _ENGINE_FAIL_PCT or hit_auto:
                    degraded.add(name)
                    sev = "critical" if hit_auto else ("high" if fail_pct >= 80 else "medium")
                    _, created = await alert_svc.upsert_alert(
                        db,
                        dedup_key=f"engine_reliability:{name}",
                        source="engine_reliability",
                        severity=sev,
                        title=(f"Engine '{name}' auto-disabled at {fail_pct}% failures"
                               if hit_auto
                               else f"Engine '{name}' failing {fail_pct}% of runs"),
                        description=f"{failed}/{runs} runs failed over the last {_ENGINE_WINDOW_DAYS}d.",
                        target_type="engine", target_id=name,
                        detail={"runs": runs, "failed": failed, "fail_pct": fail_pct,
                                "auto_disabled": hit_auto},
                    )
                    counts["opened" if created else "updated"] += 1
            counts["auto_disabled"] += len(auto_disabled_this_tick)
            # Auto-resolve engines that recovered.
            open_eng = await db.scalars(
                select(Alert).where(Alert.source == "engine_reliability",
                                    Alert.status.in_(("open", "acknowledged")))
            )
            for a in open_eng.all():
                if a.target_id not in degraded:
                    if await alert_svc.auto_resolve(db, a.dedup_key,
                                                    note="Engine reliability recovered."):
                        counts["resolved"] += 1

            # 3) Worker liveness + 4) queue depth (Redis).
            await _check_infra(db, now, counts, alert_svc)
            # 5) Suspicious admin behavior — IP burst + privileged-action burst.
            await _check_admin_anomalies(db, now, counts, alert_svc)

            await db.commit()
    finally:
        await engine.dispose()

    await alert_svc.publish_alert_event({"type": "evaluated", **counts})
    if any(counts.values()):
        logger.info("alert evaluation: %s", counts)
    return counts


async def _check_infra(db, now, counts, alert_svc) -> None:
    import os
    import redis.asyncio as aioredis

    try:
        r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                              socket_connect_timeout=2, decode_responses=True)
        await r.ping()
    except Exception:  # noqa: BLE001
        return  # no Redis → can't assess worker/queue; infra tile already shows it

    try:
        beat = await r.get("webhound:worker:heartbeat")
        age = (now.timestamp() - float(beat)) if beat else None
        if age is None or age > _WORKER_STALE_S:
            _, created = await alert_svc.upsert_alert(
                db, dedup_key="worker_down", source="worker_down", severity="critical",
                title="Celery worker heartbeat stale",
                description=("No worker heartbeat recorded." if age is None
                             else f"Last heartbeat {int(age)}s ago (threshold {_WORKER_STALE_S}s)."),
                detail={"age_s": age},
            )
            counts["opened" if created else "updated"] += 1
        else:
            if await alert_svc.auto_resolve(db, "worker_down", note="Worker heartbeat healthy."):
                counts["resolved"] += 1

        depth = int(await r.llen("celery"))
        if depth >= _QUEUE_WARN:
            _, created = await alert_svc.upsert_alert(
                db, dedup_key="queue_backup", source="queue_backup",
                severity="high" if depth >= _QUEUE_CRIT else "medium",
                title=f"Scan queue backed up ({depth} pending)",
                description=f"Celery queue depth {depth} (warn {_QUEUE_WARN}, crit {_QUEUE_CRIT}).",
                detail={"queue_depth": depth},
            )
            counts["opened" if created else "updated"] += 1
        else:
            if await alert_svc.auto_resolve(db, "queue_backup", note="Queue drained."):
                counts["resolved"] += 1
    finally:
        try:
            await r.aclose()
        except Exception:  # noqa: BLE001
            pass


# Suspicious-admin thresholds. Conservative — only fire on signals that a
# legitimate admin would rarely hit.
_ADMIN_IP_BURST_HOURS    = 24
_ADMIN_IP_BURST_MIN      = 3          # distinct login IPs in the window
_ADMIN_ACTION_BURST_MIN  = 15         # privileged actions in last 15 min
_ADMIN_ACTION_BURST_MINS = 15


async def _check_admin_anomalies(db, now, counts, alert_svc) -> None:
    """Detect compromised-admin signatures. Two heuristics:

    A) IP burst: a staff account has logged in from >= N distinct IPs in the
       last 24h (per ip_device_fingerprints). Legitimate roaming is rare;
       attacker reuse from many proxies is common.
    B) Action burst: a staff account has performed >= N privileged actions
       in the last 15 minutes (per admin_audit_logs). Burst-scripted abuse.

    Both upsert per-user alerts via the existing source='admin_anomaly' lane,
    so they roll up into a single incident through the correlator.
    """
    from datetime import timedelta as _td

    from sqlalchemy import func as _func, select as _select

    from apps.api.models.abuse import IPDeviceFingerprint
    from apps.api.models.admin_audit_log import AdminAuditLog
    from apps.api.models.user import User

    staff = (await db.scalars(
        _select(User).where(User.admin_role != "none")
    )).all()
    if not staff:
        return

    ip_window_start = now - _td(hours=_ADMIN_IP_BURST_HOURS)
    action_window_start = now - _td(minutes=_ADMIN_ACTION_BURST_MINS)

    flagged_now: set[str] = set()
    for user in staff:
        distinct_ips = await db.scalar(
            _select(_func.count(_func.distinct(IPDeviceFingerprint.ip_address))).where(
                IPDeviceFingerprint.user_id == user.id,
                IPDeviceFingerprint.last_seen_at >= ip_window_start,
            )
        ) or 0
        actions = await db.scalar(
            _select(_func.count()).select_from(AdminAuditLog).where(
                AdminAuditLog.actor_user_id == user.id,
                AdminAuditLog.created_at >= action_window_start,
            )
        ) or 0

        reasons: list[str] = []
        detail: dict = {"distinct_ips_24h": int(distinct_ips),
                        "actions_15m": int(actions),
                        "ip_threshold": _ADMIN_IP_BURST_MIN,
                        "action_threshold": _ADMIN_ACTION_BURST_MIN}
        if int(distinct_ips) >= _ADMIN_IP_BURST_MIN:
            reasons.append("ip_burst")
        if int(actions) >= _ADMIN_ACTION_BURST_MIN:
            reasons.append("action_burst")

        if not reasons:
            # Auto-resolve any prior alert for this user that has cleared.
            if await alert_svc.auto_resolve(
                db, f"admin_anomaly:{user.id}",
                note="Admin activity returned to baseline.",
            ):
                counts["resolved"] += 1
            continue

        flagged_now.add(str(user.id))
        sev = "critical" if "ip_burst" in reasons and "action_burst" in reasons else "high"
        title = f"Suspicious admin activity: {user.email}"
        if "ip_burst" in reasons and "action_burst" in reasons:
            desc = (f"{user.email} logged in from {distinct_ips} distinct IPs in "
                    f"the last {_ADMIN_IP_BURST_HOURS}h AND performed "
                    f"{actions} privileged actions in the last "
                    f"{_ADMIN_ACTION_BURST_MINS} min.")
        elif "ip_burst" in reasons:
            desc = (f"{user.email} logged in from {distinct_ips} distinct IPs "
                    f"in the last {_ADMIN_IP_BURST_HOURS}h "
                    f"(threshold {_ADMIN_IP_BURST_MIN}).")
        else:
            desc = (f"{user.email} performed {actions} privileged actions in the "
                    f"last {_ADMIN_ACTION_BURST_MINS} min "
                    f"(threshold {_ADMIN_ACTION_BURST_MIN}).")

        _, created = await alert_svc.upsert_alert(
            db, dedup_key=f"admin_anomaly:{user.id}",
            source="admin_anomaly", severity=sev,
            title=title, description=desc,
            target_type="user", target_id=str(user.id),
            detail={**detail, "reasons": reasons},
        )
        counts["opened" if created else "updated"] += 1
