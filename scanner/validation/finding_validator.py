# WebHound — scanner/validation/finding_validator.py
# Phase-12: compare one scan's findings against a target's ground truth.
# Produces the TP / FN / FP record the precision/recall/coverage reports
# aggregate. Pure.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from validation.ground_truth import ExpectedFinding, GroundTruthTarget


@dataclass
class FindingOutcome:
    expected: ExpectedFinding
    detected: bool
    matched_titles: list[str] = field(default_factory=list)


@dataclass
class TargetValidation:
    target_name: str
    category: str
    framework: str | None
    true_positives: list[FindingOutcome] = field(default_factory=list)
    false_negatives: list[FindingOutcome] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int | None = None
    risk_in_range: bool = True
    framework_detected: str | None = None
    framework_correct: bool = True

    @property
    def tp(self) -> int:
        return len(self.true_positives)

    @property
    def fn(self) -> int:
        return len(self.false_negatives)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def passed(self) -> bool:
        return (self.fn == 0 and self.fp == 0 and self.risk_in_range
                and self.framework_correct)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "category": self.category,
            "framework": self.framework,
            "framework_detected": self.framework_detected,
            "framework_correct": self.framework_correct,
            "passed": self.passed,
            "true_positives": self.tp,
            "false_negatives": self.fn,
            "false_positives": self.fp,
            "risk_score": self.risk_score,
            "risk_in_range": self.risk_in_range,
            "missed": [
                {"engine": o.expected.engine,
                 "title": o.expected.title_substring}
                for o in self.false_negatives
            ],
            "false_positive_findings": list(self.false_positives),
        }


def validate_target(target: GroundTruthTarget, result: Any) -> TargetValidation:
    """Compare a ScanResult against a target's ground truth."""
    findings = list(getattr(result, "active_findings", []) or [])
    tv = TargetValidation(
        target_name=target.name, category=target.category,
        framework=target.framework,
    )

    # Expected findings → TP or FN.
    for exp in target.expected_findings:
        matches = [f for f in findings if exp.matches(f)]
        outcome = FindingOutcome(
            expected=exp, detected=bool(matches),
            matched_titles=[getattr(m, "title", "") for m in matches[:5]],
        )
        if matches:
            tv.true_positives.append(outcome)
        else:
            tv.false_negatives.append(outcome)

    # Forbidden findings that appear → FP.
    for exp in target.forbidden_findings:
        for f in findings:
            if exp.matches(f):
                tv.false_positives.append({
                    "engine": exp.engine,
                    "title": getattr(f, "title", ""),
                    "severity": getattr(getattr(f, "severity", None),
                                        "value", "unknown"),
                })

    # Risk window.
    meta = getattr(result, "metadata", {}) or {}
    tv.risk_score = meta.get("risk_score")
    if tv.risk_score is not None:
        if (target.expected_risk_min is not None
                and tv.risk_score < target.expected_risk_min):
            tv.risk_in_range = False
        if (target.expected_risk_max is not None
                and tv.risk_score > target.expected_risk_max):
            tv.risk_in_range = False

    # Framework detection.
    fw = (meta.get("frameworks") or {}).get("primary_framework")
    tv.framework_detected = fw
    if target.framework is not None:
        tv.framework_correct = (fw == target.framework)

    return tv


def validate_run(benchmark_run: Any) -> list[TargetValidation]:
    """Validate every TargetRun in a BenchmarkRun."""
    return [validate_target(r.target, r.result) for r in benchmark_run.runs]
