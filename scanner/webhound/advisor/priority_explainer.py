# WebHound — scanner/webhound/advisor/priority_explainer.py
# Phase-15 Task 3: explain WHY a finding ranks where it does — its share
# of the risk score and the surface it affects. So a customer reads
# "this is #1 because it's 27% of your risk and affects authentication"
# instead of an unexplained ordering.
#
# Reuses the same trust-weighted contribution the risk scorer uses, so
# the percentages are honest (they sum across scored findings).

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webhound.advisor.business_impact import assess_impact
from webhound.core.trust_policy import confidence_label_of, finding_type_of
from webhound.models.severity import Severity

# Mirror risk_scoring's weights so the contribution math matches the
# actual score the customer sees.
_BASE = {Severity.CRITICAL: 35.0, Severity.HIGH: 20.0,
         Severity.MEDIUM: 8.0, Severity.LOW: 2.0}
_TYPE = {"confirmed_risk": 1.0, "likely_risk": 0.75,
         "heuristic_signal": 0.15, "hardening": 0.20, "inventory": 0.0}
_CONF = {"confirmed": 1.0, "high": 1.0, "medium": 0.5, "low": 0.25,
         "heuristic": 1.0}


def _contribution(f: Any) -> float:
    sev = getattr(f, "severity", Severity.INFO)
    if sev not in _BASE:
        return 0.0
    ftype = finding_type_of(f)
    return (_BASE[sev] * _TYPE.get(ftype, 0.15)
            * _CONF.get(confidence_label_of(f), 1.0))


@dataclass
class PriorityExplanation:
    rank: int
    risk_share_pct: float
    affected_surface: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "risk_share_pct": round(self.risk_share_pct, 1),
            "affected_surface": self.affected_surface,
            "explanation": self.explanation,
        }


# Most-actionable dimension first — on a tie we name the specific
# surface (payment/auth/data) over the diffuse one (trust/operations).
_SURFACE_PREFERENCE = (
    "payment_risk", "authentication_risk", "data_exposure_risk",
    "customer_trust", "business_operations", "revenue",
)
_SURFACE_LABEL = {
    "payment_risk": "your payment surface",
    "authentication_risk": "your authentication surface",
    "data_exposure_risk": "sensitive data",
    "customer_trust": "customer trust",
    "business_operations": "site operations",
    "revenue": "revenue",
}


def _surface(f: Any) -> str:
    imp = assess_impact(f)
    # Pick the highest-impact dimension; break ties by actionability.
    best_dim, best_rank = None, -1
    for dim in _SURFACE_PREFERENCE:
        level = imp.dimensions.get(dim)
        if level is not None and level.rank > best_rank:
            best_dim, best_rank = dim, level.rank
    if best_dim and best_rank > 0:
        return _SURFACE_LABEL[best_dim]
    cat = getattr(getattr(f, "category", None), "value", "")
    return {"security_header": "browser security posture",
            "cookie": "session security",
            "api": "your API surface",
            "compromise": "site integrity"}.get(cat, "your site")


def explain_priorities(grouped_findings: list[Any]) -> list[PriorityExplanation]:
    """Rank scored findings by contribution and explain each one's share.

    INFO/inventory (zero contribution) are excluded — they don't compete
    for priority."""
    scored = [(f, _contribution(f)) for f in grouped_findings]
    scored = [(f, c) for f, c in scored if c > 0]
    total = sum(c for _, c in scored) or 1.0
    scored.sort(key=lambda fc: fc[1], reverse=True)

    out: list[PriorityExplanation] = []
    for i, (f, c) in enumerate(scored, 1):
        share = c / total * 100
        surface = _surface(f)
        title = getattr(f, "title", "this issue")
        if i == 1:
            lead = "This is your top priority"
        elif share >= 15:
            lead = f"This is ranked #{i}"
        else:
            lead = f"This is ranked #{i}"
        explanation = (
            f"{lead} because it contributes about {share:.0f}% of your "
            f"current risk score and affects {surface}.")
        out.append(PriorityExplanation(
            rank=i, risk_share_pct=share,
            affected_surface=surface, explanation=explanation))
    return out
