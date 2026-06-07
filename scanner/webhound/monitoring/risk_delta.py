# WebHound — scanner/webhound/monitoring/risk_delta.py
# Phase-11 Task 5: explain how risk moved between two scans.
#
# Consumes the metadata both scans already produce
# (risk_score / risk_level / risk_breakdown from core.risk_scoring) and
# produces a customer-facing RiskDelta: did risk go up, down, or hold —
# and WHY, in terms of finding-type movement (more confirmed risks, a
# removed hardening gap, etc.). Pure — no scan, no network.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.monitoring.change_history import RiskDirection

# Score move smaller than this is "noise", reported as unchanged.
_NOISE_BAND = 2


@dataclass
class RiskDelta:
    direction: RiskDirection
    previous_score: int
    current_score: int
    previous_level: str
    current_level: str
    score_change: int
    reasons: list[str] = field(default_factory=list)

    @property
    def level_changed(self) -> bool:
        return self.previous_level != self.current_level

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction.value,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "score_change": self.score_change,
            "previous_level": self.previous_level,
            "current_level": self.current_level,
            "level_changed": self.level_changed,
            "reasons": list(self.reasons),
        }


def _type_totals(meta: dict[str, Any]) -> dict[str, float]:
    bd = (meta or {}).get("risk_breakdown") or {}
    return bd.get("type_totals") or {}


def _type_counts(meta: dict[str, Any]) -> dict[str, int]:
    bd = (meta or {}).get("risk_breakdown") or {}
    return bd.get("type_counts") or {}


_TYPE_LABEL = {
    "confirmed_risk": "confirmed risks",
    "likely_risk": "likely risks",
    "heuristic_signal": "heuristic signals",
    "hardening": "hardening gaps",
    "inventory": "inventory items",
}


def compute_risk_delta(
    previous_meta: dict[str, Any] | None,
    current_meta: dict[str, Any],
) -> RiskDelta:
    """Compare two scans' risk metadata.

    With no previous scan, reports UNCHANGED with a 'first scan' reason
    (a baseline can't have moved)."""
    cur_score = int((current_meta or {}).get("risk_score", 0) or 0)
    cur_level = str((current_meta or {}).get("risk_level", "safe"))

    if not previous_meta:
        return RiskDelta(
            direction=RiskDirection.UNCHANGED,
            previous_score=cur_score, current_score=cur_score,
            previous_level=cur_level, current_level=cur_level,
            score_change=0,
            reasons=["first scan — establishing the baseline"],
        )

    prev_score = int(previous_meta.get("risk_score", 0) or 0)
    prev_level = str(previous_meta.get("risk_level", "safe"))
    change = cur_score - prev_score

    if change > _NOISE_BAND:
        direction = RiskDirection.INCREASED
    elif change < -_NOISE_BAND:
        direction = RiskDirection.DECREASED
    else:
        direction = RiskDirection.UNCHANGED

    reasons: list[str] = []
    prev_counts = _type_counts(previous_meta)
    cur_counts = _type_counts(current_meta)
    # Movement in the risk-bearing types drives the explanation; order by
    # severity of the type.
    for ftype in ("confirmed_risk", "likely_risk", "heuristic_signal",
                  "hardening"):
        d = cur_counts.get(ftype, 0) - prev_counts.get(ftype, 0)
        if d > 0:
            reasons.append(f"+{d} {_TYPE_LABEL[ftype]}")
        elif d < 0:
            reasons.append(f"{d} {_TYPE_LABEL[ftype]}")

    if not reasons:
        if direction == RiskDirection.UNCHANGED:
            reasons.append("no material change in security posture")
        else:
            reasons.append(
                f"risk score moved {change:+d} with no finding-type shift "
                "(confidence/severity recalibration)"
            )

    if direction == RiskDirection.INCREASED and cur_level != prev_level:
        reasons.insert(0, f"risk level rose from {prev_level} to {cur_level}")
    elif direction == RiskDirection.DECREASED and cur_level != prev_level:
        reasons.insert(0, f"risk level fell from {prev_level} to {cur_level}")

    return RiskDelta(
        direction=direction,
        previous_score=prev_score, current_score=cur_score,
        previous_level=prev_level, current_level=cur_level,
        score_change=change, reasons=reasons,
    )
