# WebHound — scanner/webhound/advisor/action_plan.py
# Phase-15 Task 5: classify each finding into an action bucket (Fix Now /
# Fix Soon / Monitor / Informational) with estimated effort, impact, and
# risk reduction — the concrete to-do list a customer works from.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.advisor.business_impact import ImpactLevel, assess_impact
from webhound.core.trust_policy import finding_type_of
from webhound.models.severity import Severity


class ActionBucket(str, Enum):
    FIX_NOW = "fix_now"
    FIX_SOON = "fix_soon"
    MONITOR = "monitor"
    INFORMATIONAL = "informational"

    @property
    def order(self) -> int:
        return {"fix_now": 0, "fix_soon": 1, "monitor": 2,
                "informational": 3}[self.value]


class Effort(str, Enum):
    LOW = "low"          # config change / header / flag
    MEDIUM = "medium"    # code change / vendor review
    HIGH = "high"        # architecture / access redesign


@dataclass
class ActionItem:
    title: str
    bucket: ActionBucket
    effort: Effort
    estimated_impact: str           # plain-language
    risk_reduction: str             # high/medium/low
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "bucket": self.bucket.value,
            "effort": self.effort.value,
            "estimated_impact": self.estimated_impact,
            "risk_reduction": self.risk_reduction,
            "recommendation": self.recommendation,
        }


def _engine(f: Any) -> str:
    return getattr(f, "scanner_engine", "") or ""


def _effort_for(f: Any) -> Effort:
    eng = _engine(f)
    ftype = finding_type_of(f)
    if ftype == "hardening" or eng in ("security_headers", "csp_engine",
                                       "cookie_scanner", "cors"):
        return Effort.LOW                    # config / header / flag
    if eng in ("sensitive_paths",) and "admin" in (
            getattr(f, "title", "") or "").lower():
        return Effort.HIGH                   # access control redesign
    if eng in ("form_risk", "input_analysis", "third_party_domains",
               "threat_intel", "endpoint_discovery"):
        return Effort.MEDIUM
    return Effort.MEDIUM


def _bucket_for(f: Any) -> ActionBucket:
    sev = getattr(f, "severity", Severity.INFO)
    ftype = finding_type_of(f)
    if ftype == "inventory" or sev == Severity.INFO:
        return ActionBucket.INFORMATIONAL
    if sev == Severity.CRITICAL:
        return ActionBucket.FIX_NOW
    if sev == Severity.HIGH:
        # Confirmed/likely high → fix now; heuristic high → fix soon.
        return (ActionBucket.FIX_NOW
                if ftype in ("confirmed_risk", "likely_risk")
                else ActionBucket.FIX_SOON)
    if sev == Severity.MEDIUM:
        return (ActionBucket.FIX_SOON if ftype != "heuristic_signal"
                else ActionBucket.MONITOR)
    return ActionBucket.MONITOR          # low


def _risk_reduction(f: Any) -> str:
    sev = getattr(f, "severity", Severity.INFO)
    imp = assess_impact(f)
    if sev == Severity.CRITICAL or imp.max_level == ImpactLevel.HIGH:
        return "high"
    if sev.rank >= Severity.MEDIUM.rank:
        return "medium"
    return "low"


def build_action_item(f: Any, *, recommendation: str = "") -> ActionItem:
    bucket = _bucket_for(f)
    effort = _effort_for(f)
    rr = _risk_reduction(f)
    imp = assess_impact(f)
    impact_txt = (imp.summary if imp.max_level != ImpactLevel.NONE
                  else "Limited direct impact; addressing it improves "
                       "overall posture.")
    return ActionItem(
        title=getattr(f, "title", "Finding"),
        bucket=bucket, effort=effort,
        estimated_impact=impact_txt, risk_reduction=rr,
        recommendation=recommendation
        or (getattr(f, "remediation", None) or ""))


@dataclass
class ActionPlan:
    items: list[ActionItem] = field(default_factory=list)

    def by_bucket(self, bucket: ActionBucket) -> list[ActionItem]:
        return [i for i in self.items if i.bucket == bucket]

    def to_dict(self) -> dict[str, Any]:
        buckets: dict[str, list[dict[str, Any]]] = {b.value: []
                                                    for b in ActionBucket}
        for item in self.items:
            buckets[item.bucket.value].append(item.to_dict())
        return {
            "fix_now": buckets["fix_now"],
            "fix_soon": buckets["fix_soon"],
            "monitor": buckets["monitor"],
            "informational": buckets["informational"],
            "counts": {b.value: len(buckets[b.value]) for b in ActionBucket},
        }


def build_action_plan(grouped_findings: list[Any]) -> ActionPlan:
    """Build an action plan: every finding bucketed + ordered (Fix Now
    first, then by severity within bucket)."""
    items = [build_action_item(f) for f in grouped_findings]
    items.sort(key=lambda i: (i.bucket.order,
                              {"high": 0, "medium": 1, "low": 2}
                              .get(i.risk_reduction, 3)))
    return ActionPlan(items=items)
