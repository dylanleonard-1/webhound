# WebHound — scanner/webhound/wade/classifier.py
# Converts scored anomalies into Finding objects with appropriate severity,
# category, confidence, and explainable evidence.

from __future__ import annotations

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.severity import Severity
from webhound.wade.anomaly_scorer import ScoredAnomaly
from webhound.wade.confidence import compute_confidence
from webhound.wade.diff_engine import DiffType

NAME = "wade"

# WADE findings are behavioural signals, not confirmed vulnerabilities.
# We intentionally cap WADE severity at HIGH — CRITICAL is reserved for
# security engine findings that confirm an exploitable condition.
_CRITICAL_THRESHOLD = 1.1  # effectively unreachable

# Confidence threshold below which we demote severity by one level
_DOWNGRADE_THRESHOLD = 0.40

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]

# (FindingCategory, base Severity) for each diff type
_TYPE_MAP: dict[DiffType, tuple[FindingCategory, Severity]] = {
    DiffType.NEW_SCRIPT_SOURCE:     (FindingCategory.JAVASCRIPT,     Severity.HIGH),
    DiffType.CHANGED_INLINE_SCRIPT: (FindingCategory.JAVASCRIPT,     Severity.HIGH),
    DiffType.NEW_EXTERNAL_DOMAIN:   (FindingCategory.JAVASCRIPT,     Severity.MEDIUM),
    DiffType.HEADER_REGRESSION:     (FindingCategory.SECURITY_HEADER, Severity.MEDIUM),
    DiffType.COOKIE_REGRESSION:     (FindingCategory.COOKIE,          Severity.MEDIUM),
    DiffType.NEW_FORM:              (FindingCategory.FORM,             Severity.MEDIUM),
    DiffType.FORM_FIELD_CHANGE:     (FindingCategory.FORM,             Severity.MEDIUM),
    DiffType.STATUS_CODE_CHANGE:    (FindingCategory.INFORMATIONAL,    Severity.INFO),
}

_TITLES: dict[DiffType, str] = {
    DiffType.NEW_SCRIPT_SOURCE:     "New External Script Detected",
    DiffType.CHANGED_INLINE_SCRIPT: "Inline Script Changed",
    DiffType.NEW_EXTERNAL_DOMAIN:   "New External Domain Contacted",
    DiffType.HEADER_REGRESSION:     "Security Header Regression",
    DiffType.COOKIE_REGRESSION:     "Cookie Security Flag Regression",
    DiffType.NEW_FORM:              "New Form Detected",
    DiffType.FORM_FIELD_CHANGE:     "Form Fields Changed",
    DiffType.STATUS_CODE_CHANGE:    "Page Status Code Changed",
}


class Classifier:
    """Convert a list of :class:`ScoredAnomaly` objects into :class:`Finding` objects."""

    def classify(self, anomalies: list[ScoredAnomaly]) -> list[Finding]:
        return [self._to_finding(a) for a in anomalies]

    # ------------------------------------------------------------------

    def _to_finding(self, a: ScoredAnomaly) -> Finding:
        item = a.diff_item
        category, base_sev = _TYPE_MAP.get(
            item.diff_type, (FindingCategory.UNKNOWN, Severity.INFO)
        )
        confidence = compute_confidence(a)
        severity = _adjust_severity(base_sev, a.anomaly_score, confidence, item.diff_type)
        description = _description(item, a)

        evidence = Evidence(
            evidence_type=EvidenceType.PATTERN_MATCH,
            content=item.detail,
            location=item.url,
            confidence=confidence,
            source_engine=NAME,
            extra={
                "diff_type":       item.diff_type.value,
                "baseline_value":  item.baseline_value,
                "current_value":   item.current_value,
                "context_type":    a.context_type,
                "context_weight":  a.context_weight,
                "raw_score":       a.raw_score,
            },
        )
        return Finding(
            title=_TITLES.get(item.diff_type, "Anomaly Detected"),
            description=description,
            severity=severity,
            category=category,
            scanner_engine=NAME,
            evidence=[evidence],
            confidence=confidence,
            anomaly_score=a.anomaly_score,
            tags=["wade", "anomaly", item.diff_type.value, a.context_type],
        )


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _adjust_severity(
    base: Severity,
    anomaly_score: float,
    confidence: float,
    diff_type: DiffType,
) -> Severity:
    # Escalate: high-anomaly script changes on sensitive pages
    if (
        anomaly_score >= _CRITICAL_THRESHOLD
        and diff_type in (DiffType.NEW_SCRIPT_SOURCE, DiffType.CHANGED_INLINE_SCRIPT)
    ):
        return Severity.CRITICAL

    # Downgrade: low-confidence means weaker signal
    if confidence < _DOWNGRADE_THRESHOLD and base != Severity.INFO:
        idx = _SEVERITY_ORDER.index(base)
        return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]

    return base


def _description(item: "DiffItem", a: ScoredAnomaly) -> str:  # type: ignore[name-defined]
    ctx_note = (
        f" (context: {a.context_type}, weight: ×{a.context_weight:.1f})"
        if a.context_type != "default"
        else ""
    )
    return (
        f"{item.detail}{ctx_note}. "
        f"Anomaly score: {a.anomaly_score:.2f}. "
        f"Baseline: {item.baseline_value!r} → current: {item.current_value!r}."
    )
