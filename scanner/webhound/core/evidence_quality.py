# WebHound — webhound/core/evidence_quality.py
# Phase-5D: finding-evidence hardening. Every finding must explain
# WHY it fired. This module is the auditor: it walks the active
# findings on a ScanResult, flags any missing the contract, and emits
# a structured quality report the dashboard renders + the production-
# readiness module consumes.
#
# The contract:
#   1. ``evidence`` non-empty (except INFO findings).
#   2. ``scanner_engine`` populated.
#   3. ``evidence[0].location`` non-empty — the affected URL/resource.
#   4. ``description`` populated AND describes why the finding fired
#      (≥ 40 chars heuristic — too short = "Missing CSP" alone, not
#      a reason).
#   5. ``severity_rationale`` populated for non-INFO findings.
#   6. ``confidence_rationale`` populated for non-INFO findings.
#
# Failures are reported via :class:`EvidenceQualityReport`; the
# orchestrator does NOT mutate findings on failure — the audit is
# advisory, not destructive. The dashboard renders a quality badge
# next to each finding ("evidence: complete" vs "evidence:
# incomplete — see report").

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.models.finding import Finding
from webhound.models.severity import Severity


@dataclass
class FindingQualityIssue:
    """One finding that doesn't satisfy the evidence contract.

    ``finding_id`` references the Finding.id so the dashboard can
    link directly. ``missing_fields`` is the canonical reason list;
    ``violations`` is the human-readable rendering."""

    finding_id: str
    title: str
    scanner_engine: str
    missing_fields: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "scanner_engine": self.scanner_engine,
            "missing_fields": list(self.missing_fields),
            "violations": list(self.violations),
        }


@dataclass
class EvidenceQualityReport:
    total_findings: int = 0
    complete_findings: int = 0
    incomplete_findings: list[FindingQualityIssue] = field(
        default_factory=list,
    )
    # Per-engine count of incomplete findings — flags engines that
    # systematically skip evidence (an actionable signal for the
    # operator).
    per_engine_incomplete_count: dict[str, int] = field(
        default_factory=dict,
    )

    @property
    def completeness_ratio(self) -> float:
        if self.total_findings == 0:
            return 1.0
        return round(self.complete_findings / self.total_findings, 4)

    @property
    def has_gaps(self) -> bool:
        return bool(self.incomplete_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "complete_findings": self.complete_findings,
            "completeness_ratio": self.completeness_ratio,
            "has_gaps": self.has_gaps,
            "incomplete_count": len(self.incomplete_findings),
            "incomplete_findings": [
                i.to_dict() for i in self.incomplete_findings
            ],
            "per_engine_incomplete_count":
                dict(self.per_engine_incomplete_count),
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


_MIN_DESCRIPTION_LEN = 40


def audit_findings(findings: list[Finding]) -> EvidenceQualityReport:
    """Walk ``findings`` and emit an :class:`EvidenceQualityReport`.

    Findings already marked ``suppressed`` or ``false_positive`` are
    skipped — by definition they're operator-acknowledged and not
    user-visible."""
    report = EvidenceQualityReport()
    for f in findings:
        if getattr(f, "suppressed", False) or getattr(f, "false_positive", False):
            continue
        report.total_findings += 1
        issue = _check_one(f)
        if issue is None:
            report.complete_findings += 1
            continue
        report.incomplete_findings.append(issue)
        engine = f.scanner_engine or "<no engine>"
        report.per_engine_incomplete_count[engine] = (
            report.per_engine_incomplete_count.get(engine, 0) + 1
        )
    return report


def _check_one(f: Finding) -> FindingQualityIssue | None:
    missing: list[str] = []
    violations: list[str] = []
    is_info = (f.severity == Severity.INFO)
    if not f.scanner_engine:
        missing.append("scanner_engine")
        violations.append("scanner_engine is empty")
    if not f.evidence and not is_info:
        missing.append("evidence")
        violations.append(
            "no evidence items attached (required for non-INFO findings)",
        )
    if f.evidence:
        first = f.evidence[0]
        if not getattr(first, "location", None):
            missing.append("evidence_location")
            violations.append(
                "evidence[0].location empty — finding doesn't say "
                "where it was observed",
            )
    if not (f.description and len(f.description.strip())
             >= _MIN_DESCRIPTION_LEN):
        missing.append("description")
        violations.append(
            f"description shorter than {_MIN_DESCRIPTION_LEN} chars "
            "— not enough to explain why the finding fired",
        )
    if not is_info:
        if not (f.severity_rationale and f.severity_rationale.strip()):
            missing.append("severity_rationale")
            violations.append(
                "severity_rationale empty — finding doesn't justify "
                f"its {f.severity.value} severity",
            )
        if not (f.confidence_rationale
                 and f.confidence_rationale.strip()):
            missing.append("confidence_rationale")
            violations.append(
                "confidence_rationale empty — finding doesn't justify "
                f"its confidence={f.confidence}",
            )
    if not missing:
        return None
    return FindingQualityIssue(
        finding_id=str(getattr(f, "id", "")),
        title=f.title or "<no title>",
        scanner_engine=f.scanner_engine or "",
        missing_fields=missing,
        violations=violations,
    )
