# WebHound — webhound/wade/quality_review.py
# Phase-5H: WADE quality review — advisory analyzer that walks the
# completed scan output and surfaces findings that look weak /
# duplicative / under-corroborated / overscored.
#
# HARD CONSTRAINTS (per Phase-5H spec):
#   * WADE MUST NOT invent findings.
#   * WADE MUST NOT invent evidence.
#   * WADE MUST NOT override scanner results.
#   * WADE is advisory only.
#
# The output is a list of :class:`QualityNote` objects pinned to a
# real ``finding_id``, carrying a ``reason`` + ``recommendation`` the
# operator can act on (mark FP, request engine improvement, accept
# as-is). Notes never mutate the findings they reference.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.models.finding import Finding
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity


@dataclass
class QualityNote:
    """One advisory observation. ``kind`` is the canonical reason
    code; ``reason`` is the human-readable explanation; ``recommendation``
    is the actionable next step."""

    finding_id: str
    title: str
    scanner_engine: str
    kind: str
    reason: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "scanner_engine": self.scanner_engine,
            "kind": self.kind,
            "reason": self.reason,
            "recommendation": self.recommendation,
        }


@dataclass
class WadeQualityReview:
    notes: list[QualityNote] = field(default_factory=list)
    # Histogram of kinds the review surfaced — feeds the dashboard's
    # 'WADE flagged N possible FPs / M missing corroborations'
    # summary chips.
    counts_by_kind: dict[str, int] = field(default_factory=dict)
    total_findings_reviewed: int = 0

    @property
    def has_notes(self) -> bool:
        return bool(self.notes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings_reviewed": self.total_findings_reviewed,
            "note_count": len(self.notes),
            "counts_by_kind": dict(self.counts_by_kind),
            "notes": [n.to_dict() for n in self.notes],
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


_LOW_CONFIDENCE_THRESHOLD = 0.55
_HIGH_SEVERITY_RANK = Severity.HIGH.rank
_DUPLICATE_TITLE_PREFIX_LEN = 36


def review_scan(result: ScanResult) -> WadeQualityReview:
    """Walk the scan's active findings and emit advisory quality notes.

    Rules (every one strictly reads-only):
      * ``possible_false_positive``  — high-severity finding with
        confidence below the low-confidence threshold AND no
        ``corroborated`` tag.
      * ``weak_evidence``            — finding with empty evidence list
        OR evidence[0].location empty, on any non-INFO severity.
      * ``duplicate_finding``        — two or more findings sharing
        the same engine + first-36-chars-of-title — only the second
        and later are flagged.
      * ``missing_corroboration``    — finding with severity ≥ HIGH
        and no corroborated_by metadata + no 'cluster' / 'correlated'
        tag.
      * ``suspicious_scoring``       — INFO finding emitting with
        ``confidence >= 0.9`` (severity says 'informational' but
        confidence says 'confirmed' — inconsistent).
    """
    review = WadeQualityReview()
    findings = list(result.active_findings)
    review.total_findings_reviewed = len(findings)
    seen_keys: set[tuple[str, str]] = set()

    for f in findings:
        for note in _evaluate_one(f, seen_keys):
            review.notes.append(note)
            review.counts_by_kind[note.kind] = (
                review.counts_by_kind.get(note.kind, 0) + 1
            )
    return review


def _evaluate_one(
    f: Finding, seen_keys: set[tuple[str, str]],
) -> list[QualityNote]:
    notes: list[QualityNote] = []
    tags = {t.lower() for t in (f.tags or [])}
    is_info = (f.severity == Severity.INFO)

    # possible_false_positive
    if (not is_info
            and f.severity.rank >= _HIGH_SEVERITY_RANK
            and (f.confidence or 0.0) < _LOW_CONFIDENCE_THRESHOLD
            and "corroborated" not in tags):
        notes.append(QualityNote(
            finding_id=str(f.id),
            title=f.title,
            scanner_engine=f.scanner_engine,
            kind="possible_false_positive",
            reason=(
                f"High-severity finding ({f.severity.value}) with "
                f"confidence {f.confidence} below "
                f"{_LOW_CONFIDENCE_THRESHOLD} and no corroboration."
            ),
            recommendation=(
                "Manually verify, then either downgrade severity to "
                "match confidence or mark as false-positive."
            ),
        ))

    # weak_evidence
    location = (f.evidence[0].location if f.evidence else "")
    if (not is_info
            and (not f.evidence or not location)):
        notes.append(QualityNote(
            finding_id=str(f.id),
            title=f.title,
            scanner_engine=f.scanner_engine,
            kind="weak_evidence",
            reason=(
                "Finding emitted without a concrete evidence URL — "
                "operators can't reproduce the observation."
            ),
            recommendation=(
                "Engine should attach the page/resource URL it was "
                "looking at when the rule fired."
            ),
        ))

    # duplicate_finding (engine + title-prefix)
    key = (
        (f.scanner_engine or "").lower(),
        (f.title or "")[:_DUPLICATE_TITLE_PREFIX_LEN].lower(),
    )
    if key in seen_keys:
        notes.append(QualityNote(
            finding_id=str(f.id),
            title=f.title,
            scanner_engine=f.scanner_engine,
            kind="duplicate_finding",
            reason=(
                "Another finding from the same engine shares this "
                "title prefix — likely the grouper missed a merge."
            ),
            recommendation=(
                "If both are real, refine titles; if they're the "
                "same issue, mark one as duplicate or add the engine "
                "to _PER_URL_ENGINES tuning."
            ),
        ))
    else:
        seen_keys.add(key)

    # missing_corroboration
    md = f.metadata or {}
    corroborated_by = md.get("corroborated_by") or []
    cluster_membership = ("cluster" in tags or "correlated" in tags)
    if (not is_info
            and f.severity.rank >= _HIGH_SEVERITY_RANK
            and not corroborated_by
            and not cluster_membership):
        notes.append(QualityNote(
            finding_id=str(f.id),
            title=f.title,
            scanner_engine=f.scanner_engine,
            kind="missing_corroboration",
            reason=(
                f"{f.severity.value} severity but no other engine "
                "independently confirmed the pattern."
            ),
            recommendation=(
                "Verify the threat model. High-severity claims "
                "benefit from a corroborating signal — consider "
                "adding a correlation rule."
            ),
        ))

    # suspicious_scoring
    if is_info and (f.confidence or 0.0) >= 0.9:
        notes.append(QualityNote(
            finding_id=str(f.id),
            title=f.title,
            scanner_engine=f.scanner_engine,
            kind="suspicious_scoring",
            reason=(
                "INFO severity paired with high confidence — the "
                "engine is sure something is true but rates it as "
                "informational. One of the two is probably wrong."
            ),
            recommendation=(
                "Decide whether the engine should promote severity "
                "above INFO or whether confidence should be lowered."
            ),
        ))
    return notes
