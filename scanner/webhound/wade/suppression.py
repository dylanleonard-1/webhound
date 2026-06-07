# WebHound — scanner/webhound/wade/suppression.py
# WADE 2.0 alert-fatigue control (Task 8).
#
# WADE must NOT alert on every change. The diff engine deliberately emits a
# *complete* change record (so the timeline is whole); this layer decides
# which of those changes actually warrant a customer-facing alert. Everything
# suppressed is still recorded — it is hidden from alerts, not discarded.
#
# Suppressed by design:
#   * expected deployments        (status flips, tech bumps, DOM reshuffles)
#   * normal content / blog / marketing-copy / image updates
#   * minor structural DOM churn
#   * benign housekeeping          (a security header *added*, a resource removed)
#
# Never suppressed:
#   * anything security-relevant   (suspicious script / iframe / redirect,
#     possible compromise, confirmed malicious indicator)
#   * security regressions         (header dropped, cookie lost a flag)

from __future__ import annotations

from dataclasses import dataclass

from webhound.wade.change_classifier import ChangeAssessment
from webhound.wade.change_types import (
    SECURITY_RELEVANT_CHANGE_TYPES,
    ChangeBand,
    WadeChangeType,
)
from webhound.wade.diff_engine import DiffType

# Change types that are pure noise for alerting purposes.
_SUPPRESSIBLE_CHANGE_TYPES: frozenset[WadeChangeType] = frozenset({
    WadeChangeType.EXPECTED_DEPLOYMENT,
    WadeChangeType.NORMAL_CONTENT_UPDATE,
})

# Diff types that are never, on their own, worth an alert — they describe
# housekeeping or improvements rather than risk.
_ALWAYS_SUPPRESSIBLE_DIFFS: frozenset[DiffType] = frozenset({
    DiffType.HEADER_ADDED,            # a header appearing is a *good* thing
    DiffType.REMOVED_SCRIPT_SOURCE,
    DiffType.REMOVED_EXTERNAL_DOMAIN,
    DiffType.REMOVED_THIRD_PARTY_DOMAIN,
    DiffType.REMOVED_API_ENDPOINT,
    DiffType.DOM_STRUCTURE_CHANGE,
    DiffType.TECHNOLOGY_CHANGE,
    DiffType.STATUS_CODE_CHANGE,
})

# Security regressions: even though they aren't in the "suspicious" change-type
# family, they must always alert — a dropped header / lost cookie flag is a
# real degradation.
_NEVER_SUPPRESS_DIFFS: frozenset[DiffType] = frozenset({
    DiffType.HEADER_REGRESSION,
    DiffType.COOKIE_REGRESSION,
})


@dataclass(frozen=True)
class SuppressionDecision:
    suppressed: bool
    reason: str


def decide(assessment: ChangeAssessment, diff_type: DiffType) -> SuppressionDecision:
    """Decide whether a change should be hidden from alerts.

    The change is always preserved in the timeline regardless — this only
    governs whether it surfaces as a finding/alert."""
    # 1. Security-relevant intent always alerts.
    if assessment.change_type in SECURITY_RELEVANT_CHANGE_TYPES:
        return SuppressionDecision(False, "security-relevant change")

    # 2. Explicit security regressions always alert.
    if diff_type in _NEVER_SUPPRESS_DIFFS:
        return SuppressionDecision(False, "security regression")

    # 3. Housekeeping diff types never alert on their own.
    if diff_type in _ALWAYS_SUPPRESSIBLE_DIFFS:
        return SuppressionDecision(
            True, f"{diff_type.value} is housekeeping, not a security signal"
        )

    # 4. Expected deployment / normal content updates are suppressed.
    if assessment.change_type in _SUPPRESSIBLE_CHANGE_TYPES:
        return SuppressionDecision(
            True, f"{assessment.change_type.value} — expected/benign change"
        )

    # 5. Very-low band benign vendor additions: keep as quiet inventory, do
    #    not suppress entirely (the customer still wants the vendor list), but
    #    they're informational. We surface them — only true noise is hidden.
    return SuppressionDecision(False, "retained for vendor inventory / review")


def should_suppress(assessment: ChangeAssessment, diff_type: DiffType) -> bool:
    """Convenience boolean form of :func:`decide`."""
    return decide(assessment, diff_type).suppressed
