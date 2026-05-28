# WebHound — apps/api/telemetry.py
# Centralized operational telemetry contracts. Every module that wants its
# events to show up in the live SOC stream uses this module's Event envelope
# + publish_event(). One channel, one shape, one severity vocabulary — keeps
# the SSE subscriber, audit, and incident correlator on the same page.

from __future__ import annotations

import enum
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

# Single channel that the layout's SSE subscriber listens on (Phase 3).
# Existing alert publishes already use this — telemetry events ride alongside.
EVENT_CHANNEL = "webhound:alerts:events"


class OperationalStatus(str, enum.Enum):
    """How an operational surface is doing right now. Maps to a UI color."""
    OPERATIONAL = "operational"   # everything green
    DEGRADED = "degraded"         # working but slow / partially failing
    OFFLINE = "offline"           # not responding
    MAINTENANCE = "maintenance"   # intentionally paused by staff


class Severity(str, enum.Enum):
    """Shared severity vocabulary across alerts, incidents, abuse, logs."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 10, Severity.MEDIUM: 20,
             Severity.HIGH: 30, Severity.CRITICAL: 40}


def severity_rank(s: str | Severity) -> int:
    try:
        return _SEV_RANK[Severity(s)]
    except (ValueError, KeyError):
        return 0


def max_severity(*values: str | Severity) -> Severity:
    return max((Severity(v) for v in values if v), key=lambda v: _SEV_RANK[v],
               default=Severity.INFO)


class EventKind(str, enum.Enum):
    """Stable kind codes — UI filters and incident correlation key off these.

    Naming: `<domain>.<verb>`. New kinds are additive — never rename an
    existing one without a deprecation path because the SSE consumer + the
    incident correlator already match on them.
    """
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    ALERT_OPENED = "alert.opened"
    ALERT_UPDATED = "alert.updated"
    ALERT_ACK = "alert.ack"
    ALERT_RESOLVED = "alert.resolved"

    INCIDENT_OPENED = "incident.opened"
    INCIDENT_STATUS = "incident.status"

    AUTH_LOGIN = "auth.login"
    AUTH_SUSPICIOUS_LOGIN = "auth.suspicious_login"

    CUSTOMER_SUSPENDED = "customer.suspended"
    CUSTOMER_REACTIVATED = "customer.reactivated"
    CUSTOMER_PLAN_CHANGED = "customer.plan_changed"

    BILLING_PAYMENT_FAILED = "billing.payment_failed"
    BILLING_SUB_CHANGED = "billing.sub_changed"

    INFRA_WORKER_DOWN = "infra.worker_down"
    INFRA_WORKER_RECOVERED = "infra.worker_recovered"
    INFRA_QUEUE_BACKUP = "infra.queue_backup"

    ENGINE_DEGRADED = "engine.degraded"
    ENGINE_RECOVERED = "engine.recovered"
    ENGINE_MAINTENANCE = "engine.maintenance"

    ABUSE_FLAG_OPENED = "abuse.flag_opened"
    ABUSE_USER_BANNED = "abuse.user_banned"

    TICKET_OPENED = "ticket.opened"
    TICKET_SLA_BREACH = "ticket.sla_breach"

    DEPLOY_RECORDED = "deploy.recorded"

    ADMIN_ACTION = "admin.action"


@dataclass
class Event:
    """Operational event envelope. Always carry kind + severity + source.

    `target_type` + `target_id` let the UI deep-link (e.g. open the scan a
    `scan.failed` event references). `detail` is a small JSON blob — keep it
    flat and short; this rides on every SSE frame and shouldn't be huge."""
    kind: EventKind | str
    severity: Severity | str = Severity.INFO
    source: str = "platform"
    message: str = ""
    target_type: str | None = None
    target_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    actor_email: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_payload(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value if isinstance(self.kind, EventKind) else self.kind
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        d["at"] = self.at.isoformat()
        return d


async def publish_event(event: Event) -> None:
    """Best-effort fan-out. Writes one frame to the Redis pub/sub channel the
    SSE handler subscribes to. Never raises — operational telemetry must not
    take down the path that emitted it."""
    payload = event.to_payload()
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=2)
        try:
            await r.publish(EVENT_CHANNEL, json.dumps(payload))
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        logger.debug("publish_event failed", exc_info=True)


def status_from_health(*, total: int, failed: int, skipped: int,
                       degraded_pct: float = 25.0,
                       critical_pct: float = 75.0) -> OperationalStatus:
    """Derive a simple operational status from run counts. Used by engine
    health scoring + infra summarization."""
    if total <= 0:
        return OperationalStatus.OPERATIONAL  # no data yet = trust default
    bad_pct = 100 * (failed + skipped) / total
    if bad_pct >= critical_pct:
        return OperationalStatus.OFFLINE
    if bad_pct >= degraded_pct:
        return OperationalStatus.DEGRADED
    return OperationalStatus.OPERATIONAL
