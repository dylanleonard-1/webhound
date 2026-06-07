# WebHound — scanner/validation/regression_runner.py
# Phase-12 Task 8: gate scanner changes on validation quality.
#
# Runs the lab, builds the coverage report, and compares the quality
# score against a stored baseline. If quality drops beyond a tolerance,
# the regression check FAILS — so a change that hurts detection accuracy
# can't merge silently.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from validation.coverage_report import CoverageReport, build_coverage_report
from validation.finding_validator import validate_run

# Allowed drop in the overall quality score before we fail (points).
_QUALITY_TOLERANCE = 1.0
# Hard floors a change can never push below.
_MIN_OVERALL = 60.0
_MAX_FALSE_POSITIVES = 0     # ground-truth FP guards must stay clean


@dataclass
class RegressionResult:
    passed: bool
    overall_quality: float
    baseline_quality: float | None
    quality_delta: float
    reasons: list[str] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "overall_quality": round(self.overall_quality, 1),
            "baseline_quality": (round(self.baseline_quality, 1)
                                 if self.baseline_quality is not None else None),
            "quality_delta": round(self.quality_delta, 1),
            "reasons": list(self.reasons),
        }


def evaluate_regression(
    benchmark_run: Any,
    *,
    baseline_quality: float | None = None,
) -> RegressionResult:
    """Validate a BenchmarkRun and decide pass/fail.

    ``baseline_quality`` is the previously-recorded overall score (e.g.
    stored in the repo); None means no baseline yet (records, doesn't
    gate on delta)."""
    validations = validate_run(benchmark_run)
    report: CoverageReport = build_coverage_report(validations)
    overall = report.quality.overall

    reasons: list[str] = []
    passed = True

    # Hard floor.
    if overall < _MIN_OVERALL:
        passed = False
        reasons.append(
            f"overall quality {overall:.1f} below hard floor {_MIN_OVERALL}")

    # FP guards must stay clean.
    total_fp = report.precision.get("false_positives", 0)
    if total_fp > _MAX_FALSE_POSITIVES:
        passed = False
        reasons.append(
            f"{total_fp} false positive(s) against ground-truth FP guards")

    # Regression vs baseline.
    delta = 0.0
    if baseline_quality is not None:
        delta = overall - baseline_quality
        if delta < -_QUALITY_TOLERANCE:
            passed = False
            reasons.append(
                f"quality dropped {delta:.1f} pts vs baseline "
                f"{baseline_quality:.1f} (tolerance {_QUALITY_TOLERANCE})")

    if passed and not reasons:
        reasons.append("all validation gates passed")

    return RegressionResult(
        passed=passed,
        overall_quality=overall,
        baseline_quality=baseline_quality,
        quality_delta=delta,
        reasons=reasons,
        report=report.to_dict(),
    )
