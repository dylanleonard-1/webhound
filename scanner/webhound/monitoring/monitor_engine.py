# WebHound — scanner/webhound/monitoring/monitor_engine.py
# Phase-11: the monitoring orchestrator. One entry point that ties the
# layer together — given a completed scan's metadata + the site's prior
# change history, it produces the updated history, the risk delta, the
# alerts, and the dashboard timeline.
#
# This is what the worker calls after each monitored scan. Pure: the
# caller owns loading the prior history and persisting the new one.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.monitoring.alert_manager import (
    Alert,
    active_alerts,
    build_alerts,
)
from webhound.monitoring.change_history import ChangeHistory
from webhound.monitoring.change_tracker import track_scan
from webhound.monitoring.notification_policy import (
    DeliveryPlan,
    NotificationPolicy,
    plan_delivery,
)
from webhound.monitoring.risk_delta import RiskDelta, compute_risk_delta


@dataclass
class MonitorResult:
    """Everything the monitoring pass produced for one scan."""

    history: ChangeHistory
    risk_delta: RiskDelta
    alerts: list[Alert] = field(default_factory=list)
    delivery: DeliveryPlan | None = None

    @property
    def active_alerts(self) -> list[Alert]:
        return active_alerts(self.alerts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_delta": self.risk_delta.to_dict(),
            "alert_count": len(self.alerts),
            "active_alert_count": len(self.active_alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "delivery": self.delivery.to_dict() if self.delivery else None,
            "timeline": self.history.timeline(),
            "history_summary": {
                "scan_count": self.history.scan_count,
                "total_changes": self.history.total_changes,
                "recurring_count": len(self.history.recurring),
                "tier_histogram": self.history.tier_histogram(),
                "category_histogram": self.history.category_histogram(),
            },
        }


def run_monitoring(
    *,
    current_meta: dict[str, Any],
    previous_meta: dict[str, Any] | None = None,
    prior_history: ChangeHistory | None = None,
    scan_timestamp: str,
    target: str = "",
    policy: NotificationPolicy | None = None,
) -> MonitorResult:
    """Run the full monitoring pass for one completed scan.

    ``current_meta`` / ``previous_meta`` are scan_result.metadata dicts.
    ``prior_history`` is the persisted ChangeHistory (None on first
    scan). Returns a MonitorResult; the caller persists
    ``result.history`` and acts on ``result.delivery``.

    New change events (this scan's, not previously in history) drive the
    alerts; the whole timeline is updated for the dashboard."""
    history = prior_history or ChangeHistory(target=target)
    prior_keys = set(history.records.keys())

    # 1. Accumulate this scan's WADE timeline into the history.
    track_scan(
        history,
        wade_timeline=current_meta.get("wade_timeline"),
        scan_timestamp=scan_timestamp,
        target=target,
    )

    # 2. New/changed events this scan = records whose last_seen is now.
    scan_events = [
        e for e in history.records.values()
        if e.last_seen == scan_timestamp
    ]
    # Mark which were already known so the alert manager can anti-spam.
    new_events = scan_events

    # 3. Risk delta vs the previous scan.
    risk_delta = compute_risk_delta(previous_meta, current_meta)

    # 4. Build alerts from new events + risk delta + security stories.
    #    Re-seed history.records with the PRIOR keys so 'seen_before' is
    #    computed correctly (history was already mutated in step 1).
    seen_history = ChangeHistory(target=history.target)
    for k in prior_keys:
        if k in history.records:
            seen_history.records[k] = history.records[k]
    alerts = build_alerts(
        new_events,
        history=seen_history,
        risk_delta=risk_delta,
        security_stories=current_meta.get("security_stories"),
    )

    # 5. Plan delivery under the customer's policy.
    pol = policy or NotificationPolicy()
    delivery = plan_delivery(alerts, pol)

    return MonitorResult(
        history=history, risk_delta=risk_delta,
        alerts=alerts, delivery=delivery,
    )
