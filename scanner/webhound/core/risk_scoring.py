# WebHound — scanner/webhound/core/risk_scoring.py
# Phase-7 centralized risk scoring (Task 1). THE one place severity,
# confidence, finding type, and caps combine into the 0-100 score.
#
# Two algorithms, selected per result:
#
#   TRUST-WEIGHTED (fresh scans — grouped findings carry
#   metadata.finding_type from the trust policy):
#       contribution = base(severity) × type_factor × confidence_factor
#       base:    CRITICAL 35 | HIGH 20 | MEDIUM 8 | LOW 2
#       type:    confirmed_risk ×1.0 | likely_risk ×0.75 |
#                heuristic_signal ×0.15 | hardening ×0.20 |
#                inventory ×0
#       conf:    medium ×0.5 | low ×0.25 | others ×1.0
#       caps:    hardening total ≤15 | heuristic total ≤10 |
#                security-header subtotal ≤12 | repeated
#                (engine, type) damped ×0.5 after the first
#
#   LEGACY (results without trust annotations — old persisted scans,
#   pre-Phase-7 fixtures): the Phase-2-audit quality-weighted model,
#   kept byte-compatible so historical scores don't shift.
#
# The label guards apply to both: "critical" requires a real CRITICAL
# risk finding; inventory and hardening can never drag a site into
# high/critical on volume alone.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.core.trust_policy import (
    confidence_label_of,
    finding_type_of,
)
from webhound.models.scan_result import ScanResult, SeverityBreakdown
from webhound.models.severity import Severity

# ---------------------------------------------------------------------------
# Trust-weighted model
# ---------------------------------------------------------------------------

_BASE_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 2.0,
}

_TYPE_FACTOR: dict[str, float] = {
    "confirmed_risk": 1.0,
    "likely_risk": 0.75,
    "heuristic_signal": 0.15,
    "hardening": 0.20,
    "inventory": 0.0,
}

_CONF_FACTOR: dict[str, float] = {
    "confirmed": 1.0,
    "high": 1.0,
    "medium": 0.5,
    "low": 0.25,
    # heuristic confidence is already priced into the heuristic_signal
    # type factor — applying both would double-punish.
    "heuristic": 1.0,
}

_HARDENING_CAP = 15.0
_HEURISTIC_CAP = 10.0
_HEADER_CAP = 12.0
_REPEAT_DAMP = 0.5

_RISK_TYPES = ("confirmed_risk", "likely_risk")


@dataclass
class RiskBreakdown:
    """Transparent decomposition of the score — lands in
    metadata.risk_breakdown so the dashboard can show customers WHY
    the number is what it is."""

    algorithm: str = "trust_weighted"
    score: int = 0
    level: str = "safe"
    type_totals: dict[str, float] = field(default_factory=dict)
    type_counts: dict[str, int] = field(default_factory=dict)
    caps_applied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "score": self.score,
            "level": self.level,
            "type_totals": {
                k: round(v, 2) for k, v in self.type_totals.items()
            },
            "type_counts": dict(self.type_counts),
            "caps_applied": list(self.caps_applied),
        }


def _level_for(score: int) -> str:
    if score <= 19:
        return "safe"
    if score <= 39:
        return "low"
    if score <= 59:
        return "medium"
    if score <= 79:
        return "high"
    return "critical"


def _category_value(gf: Any) -> str:
    cat = getattr(gf, "category", None)
    return getattr(cat, "value", str(cat or ""))


def _compute_trust_weighted(grouped: list[Any]) -> RiskBreakdown:
    bd = RiskBreakdown(algorithm="trust_weighted")
    totals: dict[str, float] = {t: 0.0 for t in _TYPE_FACTOR}
    counts: dict[str, int] = {t: 0 for t in _TYPE_FACTOR}
    header_subtotal = 0.0
    seen_repeat: dict[tuple[str, str], int] = {}
    # Raw risk-severity counts for the label guards.
    risk_critical = 0
    risk_high = 0

    for gf in grouped:
        severity = getattr(gf, "severity", Severity.INFO)
        if severity not in _BASE_WEIGHT:
            ftype = finding_type_of(gf)
            counts[ftype] = counts.get(ftype, 0) + 1
            continue
        ftype = finding_type_of(gf)
        if ftype not in _TYPE_FACTOR:
            ftype = "heuristic_signal"
        counts[ftype] = counts.get(ftype, 0) + 1
        if ftype in _RISK_TYPES:
            if severity == Severity.CRITICAL:
                risk_critical += 1
            elif severity == Severity.HIGH:
                risk_high += 1

        contribution = (
            _BASE_WEIGHT[severity]
            * _TYPE_FACTOR[ftype]
            * _CONF_FACTOR.get(confidence_label_of(gf), 1.0)
        )
        # Repeated (engine, type) pairs: first counts fully, the rest
        # are damped — ten variations of the same issue class are not
        # ten independent risks.
        key = (getattr(gf, "scanner_engine", "") or "", ftype)
        prior = seen_repeat.get(key, 0)
        if prior >= 1:
            contribution *= _REPEAT_DAMP
        seen_repeat[key] = prior + 1

        totals[ftype] = totals.get(ftype, 0.0) + contribution
        if ftype == "hardening" and _category_value(gf) == "security_header":
            header_subtotal += contribution

    # Caps.
    if header_subtotal > _HEADER_CAP:
        totals["hardening"] -= (header_subtotal - _HEADER_CAP)
        bd.caps_applied.append(
            f"security-header contribution capped at {_HEADER_CAP:g}"
        )
    if totals.get("hardening", 0.0) > _HARDENING_CAP:
        totals["hardening"] = _HARDENING_CAP
        bd.caps_applied.append(
            f"hardening contribution capped at {_HARDENING_CAP:g}"
        )
    if totals.get("heuristic_signal", 0.0) > _HEURISTIC_CAP:
        totals["heuristic_signal"] = _HEURISTIC_CAP
        bd.caps_applied.append(
            f"heuristic contribution capped at {_HEURISTIC_CAP:g}"
        )

    score = int(round(min(100.0, sum(max(v, 0.0) for v in totals.values()))))
    level = _level_for(score)

    # Downward guards: the scary labels require real risk findings.
    if level == "critical" and risk_critical == 0:
        level = "high"
    if level == "high" and risk_critical == 0 and risk_high == 0:
        level = "medium"
    # Upward guards: one real CRITICAL risk can't read as calm.
    if risk_critical > 0 and level in ("safe", "low", "medium"):
        level = "high"
    if risk_high > 0 and level == "safe":
        level = "low"

    bd.score = score
    bd.level = level
    bd.type_totals = totals
    bd.type_counts = counts
    return bd


# ---------------------------------------------------------------------------
# Legacy model (byte-compatible with the Phase-2 audit scorer)
# ---------------------------------------------------------------------------


def _quality_multiplier(confidence: float) -> float:
    if confidence >= 0.9:
        return 1.0
    if confidence >= 0.7:
        return 0.85
    if confidence >= 0.55:
        return 0.55
    if confidence >= 0.4:
        return 0.20
    return 0.10


def _quality_weighted_breakdown(
    grouped: list[Any],
) -> tuple[SeverityBreakdown, dict[str, float]]:
    counts = SeverityBreakdown()
    weighted: dict[str, float] = {"critical": 0.0, "high": 0.0,
                                  "medium": 0.0, "low": 0.0}
    for gf in grouped:
        conf = float(getattr(gf, "confidence", 1.0) or 0.0)
        if gf.severity == Severity.INFO:
            counts.info += 1
            continue
        mult = _quality_multiplier(conf)
        match gf.severity:
            case Severity.CRITICAL:
                counts.critical += 1
                weighted["critical"] += mult
            case Severity.HIGH:
                counts.high += 1
                weighted["high"] += mult
            case Severity.MEDIUM:
                counts.medium += 1
                weighted["medium"] += mult
            case Severity.LOW:
                counts.low += 1
                weighted["low"] += mult
    return counts, weighted


def _compute_legacy(result: ScanResult) -> tuple[int, str]:
    security_grouped = [
        gf for gf in result.grouped_findings if gf.scanner_engine != "wade"
    ] if result.grouped_findings else None

    if security_grouped:
        bd, weighted = _quality_weighted_breakdown(security_grouped)
    elif result.grouped_findings:
        bd, weighted = _quality_weighted_breakdown(result.grouped_findings)
    else:
        bd = result.severity_breakdown
        weighted = {
            "critical": float(bd.critical),
            "high":     float(bd.high),
            "medium":   float(bd.medium),
            "low":      float(bd.low),
        }

    risk = 0
    risk += min(weighted["critical"] * 30, 85)
    risk += min(weighted["high"]     * 15, 40)
    risk += min(weighted["medium"]   *  7, 30)
    risk += min(weighted["low"]      *  2, 10)
    risk = min(100, int(round(risk)))

    level = _level_for(risk)

    if level == "critical" and bd.critical == 0:
        level = "high"
    if level == "high" and bd.critical == 0 and bd.high == 0:
        level = "medium"
    if bd.critical > 0 and level in ("safe", "low", "medium"):
        level = "high"
    if bd.high > 0 and level == "safe":
        level = "low"

    return risk, level


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compute_risk_score(
    result: ScanResult,
) -> tuple[int, str, RiskBreakdown | None]:
    """Compute (score, level, breakdown) for *result*.

    Uses the trust-weighted model when grouped findings carry trust
    annotations (every fresh scan after the orchestrator's policy
    pass); falls back to the legacy quality-weighted model otherwise
    so historical results and old fixtures score identically."""
    security_grouped = [
        gf for gf in (result.grouped_findings or [])
        if gf.scanner_engine != "wade"
    ]
    annotated = [
        gf for gf in security_grouped
        if (getattr(gf, "metadata", None) or {}).get("finding_type")
    ]
    if annotated and len(annotated) == len(security_grouped):
        bd = _compute_trust_weighted(security_grouped)
        return bd.score, bd.level, bd
    risk, level = _compute_legacy(result)
    return risk, level, None
