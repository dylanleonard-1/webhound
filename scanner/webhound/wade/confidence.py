# WebHound — scanner/webhound/wade/confidence.py
# Computes confidence scores for WADE anomaly findings.
#
# Confidence reflects how certain we are that an observed change is a true
# positive, independent of how anomalous it is.  Some diff types (e.g. header
# regression) are deterministic comparisons; others (e.g. form field change)
# involve more interpretation and receive lower base confidence.

from __future__ import annotations

from webhound.wade.anomaly_scorer import ScoredAnomaly
from webhound.wade.change_types import WadeConfidence
from webhound.wade.diff_engine import DiffType

# Base confidence per diff type — how reliable the detection method is
EVIDENCE_WEIGHTS: dict[DiffType, float] = {
    DiffType.NEW_SCRIPT_SOURCE:     0.90,  # URL comparison is exact
    DiffType.CHANGED_INLINE_SCRIPT: 0.85,  # hash comparison is exact
    DiffType.NEW_EXTERNAL_DOMAIN:   0.75,  # link extraction is reliable
    DiffType.HEADER_REGRESSION:     0.80,  # header comparison is exact
    DiffType.COOKIE_REGRESSION:     0.80,  # flag comparison is exact
    DiffType.NEW_FORM:              0.70,  # form extraction is reliable
    DiffType.FORM_FIELD_CHANGE:     0.70,
    DiffType.STATUS_CODE_CHANGE:    0.90,  # status comparison is exact
    # WADE 2.0
    DiffType.REMOVED_SCRIPT_SOURCE:      0.90,  # exact URL comparison
    DiffType.REMOVED_EXTERNAL_DOMAIN:    0.75,
    DiffType.NEW_THIRD_PARTY_DOMAIN:     0.85,  # observed resource host
    DiffType.REMOVED_THIRD_PARTY_DOMAIN: 0.80,
    DiffType.NEW_API_ENDPOINT:           0.55,  # routes partly inferred from JS
    DiffType.REMOVED_API_ENDPOINT:       0.50,
    DiffType.HEADER_ADDED:               0.90,  # header comparison is exact
    DiffType.COOKIE_BEHAVIOR_CHANGE:     0.80,
    DiffType.NEW_IFRAME:                 0.90,  # iframe physically present
    DiffType.REDIRECT_CHANGE:            0.90,  # redirect chain observed
    DiffType.TECHNOLOGY_CHANGE:          0.50,  # fingerprint heuristic
    DiffType.DOM_STRUCTURE_CHANGE:       0.85,  # structural hash is exact
    DiffType.NEW_JS_ROUTE:               0.55,  # route inferred from JS/SPA
    DiffType.NEW_ADMIN_ENDPOINT:         0.70,  # admin path matched in surface
}

# Detection-method confidence *level* per diff type (Task 7). Distinct from
# the numeric weight above: this is the human-facing CONFIRMED/HIGH/…/HEURISTIC
# label. Threat-intel hits and physically-observed artifacts are CONFIRMED;
# routes inferred from JS or fingerprinted tech are LOW/HEURISTIC.
_CONFIDENCE_LEVELS: dict[DiffType, WadeConfidence] = {
    DiffType.NEW_SCRIPT_SOURCE:     WadeConfidence.CONFIRMED,
    DiffType.REMOVED_SCRIPT_SOURCE: WadeConfidence.CONFIRMED,
    DiffType.CHANGED_INLINE_SCRIPT: WadeConfidence.CONFIRMED,
    DiffType.NEW_EXTERNAL_DOMAIN:   WadeConfidence.HIGH,
    DiffType.REMOVED_EXTERNAL_DOMAIN: WadeConfidence.HIGH,
    DiffType.NEW_THIRD_PARTY_DOMAIN:  WadeConfidence.CONFIRMED,
    DiffType.REMOVED_THIRD_PARTY_DOMAIN: WadeConfidence.HIGH,
    DiffType.HEADER_REGRESSION:     WadeConfidence.CONFIRMED,
    DiffType.HEADER_ADDED:          WadeConfidence.CONFIRMED,
    DiffType.COOKIE_REGRESSION:     WadeConfidence.CONFIRMED,
    DiffType.COOKIE_BEHAVIOR_CHANGE: WadeConfidence.CONFIRMED,
    DiffType.NEW_FORM:              WadeConfidence.CONFIRMED,
    DiffType.FORM_FIELD_CHANGE:     WadeConfidence.HIGH,
    DiffType.NEW_IFRAME:            WadeConfidence.CONFIRMED,
    DiffType.REDIRECT_CHANGE:       WadeConfidence.CONFIRMED,
    DiffType.NEW_API_ENDPOINT:      WadeConfidence.LOW,   # route extracted from JS
    DiffType.REMOVED_API_ENDPOINT:  WadeConfidence.LOW,
    DiffType.TECHNOLOGY_CHANGE:     WadeConfidence.HEURISTIC,
    DiffType.STATUS_CODE_CHANGE:    WadeConfidence.CONFIRMED,
    DiffType.DOM_STRUCTURE_CHANGE:  WadeConfidence.HIGH,
    DiffType.NEW_JS_ROUTE:          WadeConfidence.LOW,        # inferred from JS
    DiffType.NEW_ADMIN_ENDPOINT:    WadeConfidence.MEDIUM,     # path-matched
}

_MIN_CONFIDENCE: float = 0.30
_HIGH_ANOMALY_THRESHOLD: float = 0.80
_HIGH_ANOMALY_BOOST: float = 0.05


def compute_confidence(anomaly: ScoredAnomaly) -> float:
    """Return confidence in [0.0, 1.0] that this anomaly is a true positive.

    Combines detection method reliability with a small boost when the anomaly
    score is very high (strong deviation increases certainty).
    """
    base = EVIDENCE_WEIGHTS.get(anomaly.diff_item.diff_type, 0.60)
    boost = _HIGH_ANOMALY_BOOST if anomaly.anomaly_score >= _HIGH_ANOMALY_THRESHOLD else 0.0
    return max(_MIN_CONFIDENCE, min(1.0, round(base + boost, 4)))


def confidence_level(
    anomaly: ScoredAnomaly,
    *,
    threat_intel_hit: bool = False,
) -> WadeConfidence:
    """Return the human-facing :class:`WadeConfidence` level for an anomaly.

    A threat-intel hit (the destination host classified as malicious/risky)
    promotes the level to CONFIRMED — independent corroboration that the
    change is not just real but dangerous.
    """
    if threat_intel_hit:
        return WadeConfidence.CONFIRMED
    return _CONFIDENCE_LEVELS.get(anomaly.diff_item.diff_type, WadeConfidence.MEDIUM)


def adjust_findings_confidence(
    findings: list,        # list[Finding] — avoid heavy import for callers
    anomalies: list[ScoredAnomaly],
) -> list:
    """Update ``Finding.confidence`` for WADE findings that match anomalies.

    Matches by (url, diff_type) stored in ``evidence[0].extra``.
    Returns the same list (mutated in-place).
    """
    lookup: dict[tuple[str, str], float] = {
        (a.diff_item.url, a.diff_item.diff_type.value): compute_confidence(a)
        for a in anomalies
    }
    for f in findings:
        if not f.evidence:
            continue
        ev = f.evidence[0]
        key = (ev.location, ev.extra.get("diff_type", ""))
        if key in lookup:
            f.confidence = lookup[key]
    return findings
