from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

# Error monitoring — captures task failures, exhausted retries, and async
# crashes. No-op unless SENTRY_DSN is set and APP_ENV != development.
_sentry_dsn = os.getenv("SENTRY_DSN", "")
if _sentry_dsn and os.getenv("APP_ENV", "development") != "development":
    try:
        import sentry_sdk
        from sentry_sdk.integrations.celery import CeleryIntegration

        sentry_sdk.init(
            dsn=_sentry_dsn,
            environment=os.getenv("APP_ENV", "production"),
            integrations=[CeleryIntegration(monitor_beat_tasks=True)],
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0") or 0),
            send_default_pii=False,
        )
    except Exception:  # noqa: BLE001 — never let monitoring setup crash the worker
        pass

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def _int_env(name: str, default: int) -> int:
    """Parse an int env var, falling back to *default* on missing/garbage."""
    try:
        return int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


# FIX 8 — scan time limits. A soft limit raises SoftTimeLimitExceeded inside the
# task (caught by run_scan, which marks the job failed/timed-out and cleans up
# browser resources); the hard limit is a backstop that SIGKILLs a wedged worker
# process. Hard must exceed soft so the task gets a chance to clean up first.
_SCAN_SOFT_TIME_LIMIT = _int_env("SCAN_SOFT_TIME_LIMIT", 600)   # 10 min
_SCAN_HARD_TIME_LIMIT = _int_env("SCAN_HARD_TIME_LIMIT", 720)   # 12 min
if _SCAN_HARD_TIME_LIMIT <= _SCAN_SOFT_TIME_LIMIT:
    _SCAN_HARD_TIME_LIMIT = _SCAN_SOFT_TIME_LIMIT + 120

celery = Celery(
    "webhound",
    broker=redis_url,
    backend=redis_url,
    include=[
        "worker.scan_tasks",
        "worker.report_tasks",
        "worker.monitoring_tasks",
        "worker.notification_tasks",
        "worker.alert_tasks",
        "worker.fraud_tasks",
        "worker.infra_tasks",
        "worker.threat_intel_tasks",
        "worker.guest_cleanup_tasks",
    ],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # FIX 8 — global default time limits (per-task overrides on run_scan below).
    # task_reject_on_worker_lost re-queues a task whose worker died (e.g. hard
    # SIGKILL or OOM) so it isn't silently lost; combined with the stale-job
    # reaper (FIX 9) this prevents jobs from getting stuck RUNNING forever.
    task_soft_time_limit=_SCAN_SOFT_TIME_LIMIT,
    task_time_limit=_SCAN_HARD_TIME_LIMIT,
    task_reject_on_worker_lost=True,
    # Beat schedule — runs every minute, finds due scan_schedules,
    # creates ScanJob rows, and enqueues run_scan for each.
    beat_schedule={
        "dispatch-scheduled-scans": {
            "task": "worker.monitoring_tasks.dispatch_scheduled_scans",
            "schedule": crontab(minute="*"),       # every minute
            "options": {"expires": 50},            # drop if not picked up in 50s
        },
        "worker-heartbeat": {
            "task": "worker.monitoring_tasks.heartbeat",
            "schedule": crontab(minute="*/5"),     # every 5 minutes
        },
        # FIX 9 — stale-job reaper. Re-enqueues lost QUEUED jobs and fails
        # hung/dead RUNNING jobs so nothing stays stuck forever.
        "reap-stale-scan-jobs": {
            "task": "worker.monitoring_tasks.reap_stale_scan_jobs",
            "schedule": crontab(minute="*/5"),     # every 5 minutes
        },
        "evaluate-alerts": {
            "task": "worker.alert_tasks.evaluate_alerts",
            "schedule": crontab(minute="*/5"),     # SOC alert evaluation, every 5 min
        },
        "evaluate-abuse": {
            "task": "worker.fraud_tasks.evaluate_abuse",
            "schedule": crontab(minute="*/15"),    # Fraud/abuse scoring, every 15 min
        },
        "sample-infra": {
            "task": "worker.infra_tasks.sample_infra",
            "schedule": crontab(minute="*/5"),     # Infra trend sample, every 5 min
        },
        "import-threat-feeds": {
            "task": "worker.threat_intel_tasks.import_threat_feeds",
            # Sunday 03:15 UTC. Opt-in via WEBHOUND_THREAT_FEEDS_ENABLED=1.
            "schedule": crontab(day_of_week="sun", hour=3, minute=15),
        },
        # Slice 4.A follow-up — daily GC of unclaimed guest scans
        # (Websites with user_id IS NULL whose scan_job is older
        # than WEBHOUND_GUEST_RETENTION_HOURS, default 24h).
        "cleanup-expired-guest-scans": {
            "task": "worker.guest_cleanup_tasks.cleanup_expired_guest_scans",
            "schedule": crontab(hour=4, minute=15),    # daily 04:15 UTC
        },
    },
)
