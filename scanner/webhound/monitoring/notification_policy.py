# WebHound — scanner/webhound/monitoring/notification_policy.py
# Phase-11 Tasks 8/9: notification policies + monitoring cadences.
#
# This is the DECISION layer — given a set of alerts and a customer's
# policy, decide what should be delivered NOW vs deferred to a digest.
# It does NOT send anything (no email/SMS this phase); delivery is a
# later integration. Pure functions over Alert objects.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from webhound.monitoring.change_history import AlertTier


class NotificationFrequency(str, Enum):
    """How eagerly the customer wants to hear about changes (Task 8)."""

    IMMEDIATE = "immediate"          # send each qualifying alert now
    DAILY_DIGEST = "daily_digest"    # batch into a daily summary
    WEEKLY_DIGEST = "weekly_digest"  # batch into a weekly summary
    CRITICAL_ONLY = "critical_only"  # only critical alerts, immediately
    CUSTOM = "custom"                # honour a per-policy min_tier


class MonitoringMode(str, Enum):
    """Re-scan cadence (Task 9)."""

    DAILY = "daily"
    EVERY_3_DAYS = "every_3_days"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    MANUAL = "manual"

    @property
    def interval_days(self) -> int | None:
        return {
            "daily": 1, "every_3_days": 3, "weekly": 7,
            "monthly": 30, "manual": None,
        }[self.value]


@dataclass(frozen=True)
class NotificationPolicy:
    """A customer's notification preference."""

    frequency: NotificationFrequency = NotificationFrequency.DAILY_DIGEST
    # For CUSTOM (and as a floor for digests): minimum tier worth sending.
    min_tier: AlertTier = AlertTier.REVIEW

    def _floor(self) -> AlertTier:
        if self.frequency == NotificationFrequency.CRITICAL_ONLY:
            return AlertTier.CRITICAL
        if self.frequency == NotificationFrequency.CUSTOM:
            return self.min_tier
        # Immediate/digests deliver REVIEW+ by default; lower tiers are
        # informational and only ever appear in a full digest view.
        return AlertTier.REVIEW

    def should_deliver(self, tier: AlertTier) -> bool:
        """Is an alert at *tier* worth delivering at all under this
        policy?"""
        return tier.rank >= self._floor().rank

    def is_immediate(self, tier: AlertTier) -> bool:
        """Should an alert at *tier* be sent NOW (vs batched)?

        Critical always goes immediately regardless of frequency — a
        compromise indicator shouldn't wait for the weekly digest."""
        if tier == AlertTier.CRITICAL:
            return True
        if self.frequency == NotificationFrequency.IMMEDIATE:
            return self.should_deliver(tier)
        if self.frequency == NotificationFrequency.CRITICAL_ONLY:
            return tier == AlertTier.CRITICAL
        if self.frequency == NotificationFrequency.CUSTOM:
            # Custom delivers everything at/above min_tier immediately.
            return self.should_deliver(tier)
        return False  # digests defer everything non-critical


@dataclass
class DeliveryPlan:
    """The split of alerts into send-now vs defer-to-digest."""

    immediate: list = None              # list[Alert]
    digest: list = None                 # list[Alert]
    suppressed: list = None             # list[Alert] (below the floor)

    def __post_init__(self) -> None:
        self.immediate = self.immediate or []
        self.digest = self.digest or []
        self.suppressed = self.suppressed or []

    def to_dict(self) -> dict:
        return {
            "immediate_count": len(self.immediate),
            "digest_count": len(self.digest),
            "below_threshold_count": len(self.suppressed),
            "immediate": [a.to_dict() for a in self.immediate],
            "digest": [a.to_dict() for a in self.digest],
        }


def plan_delivery(alerts: list, policy: NotificationPolicy) -> DeliveryPlan:
    """Split *alerts* (Alert objects with a .tier) into immediate /
    digest / below-threshold under *policy*. Already-suppressed alerts
    (alert.suppressed) never reach delivery."""
    plan = DeliveryPlan()
    for alert in alerts:
        if getattr(alert, "suppressed", False):
            continue
        tier = alert.tier if isinstance(alert.tier, AlertTier) else \
            AlertTier(alert.tier)
        if not policy.should_deliver(tier):
            plan.suppressed.append(alert)
        elif policy.is_immediate(tier):
            plan.immediate.append(alert)
        else:
            plan.digest.append(alert)
    return plan
