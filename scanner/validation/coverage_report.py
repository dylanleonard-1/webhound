# WebHound — scanner/validation/coverage_report.py
# Phase-12 Tasks 9 + 10: the overall scanner quality score + the
# marketing-metrics rollup. Combines precision/recall/framework/engine
# scorecards into one report and a single 0-100 quality score.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from validation.finding_validator import TargetValidation
from validation.framework_scorecard import (
    build_engine_scorecards,
    build_framework_scorecards,
)
from validation.precision_report import build_precision_report
from validation.recall_report import build_recall_report


@dataclass
class QualityScore:
    """The composite scanner quality score (Task 9)."""

    coverage_score: float = 0.0       # recall-based, 0-100
    precision_score: float = 0.0      # 0-100
    recall_score: float = 0.0         # 0-100
    confidence_quality_score: float = 0.0   # framework-detection accuracy, 0-100
    false_positive_score: float = 0.0       # 100 = no FPs, 0-100
    overall: float = 0.0              # weighted composite, 0-100

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage_score": round(self.coverage_score, 1),
            "precision_score": round(self.precision_score, 1),
            "recall_score": round(self.recall_score, 1),
            "confidence_quality_score": round(self.confidence_quality_score, 1),
            "false_positive_score": round(self.false_positive_score, 1),
            "overall_quality_score": round(self.overall, 1),
        }


@dataclass
class CoverageReport:
    quality: QualityScore
    precision: dict[str, Any] = field(default_factory=dict)
    recall: dict[str, Any] = field(default_factory=dict)
    framework_scorecards: dict[str, Any] = field(default_factory=dict)
    engine_scorecards: dict[str, Any] = field(default_factory=dict)
    targets_total: int = 0
    targets_passed: int = 0

    @property
    def pass_rate(self) -> float:
        return round(self.targets_passed / self.targets_total, 4) \
            if self.targets_total else 1.0

    def marketing_metrics(self) -> dict[str, Any]:
        """Task 10 — internal-first marketing stats."""
        return {
            "coverage_pct": self.recall.get("coverage_pct", 0.0),
            "detection_rate_pct": round(self.recall.get("recall", 0.0) * 100, 1),
            "false_positive_rate_pct": round(
                (1 - self.precision.get("precision", 1.0)) * 100, 1),
            "framework_coverage": {
                fw: c["coverage_pct"]
                for fw, c in self.framework_scorecards.items()
            },
            "overall_quality_score": self.quality.overall,
            "_disclaimer": "internal metrics — verify before public use",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "quality_score": self.quality.to_dict(),
            "targets_total": self.targets_total,
            "targets_passed": self.targets_passed,
            "pass_rate": self.pass_rate,
            "precision": self.precision,
            "recall": self.recall,
            "framework_scorecards": self.framework_scorecards,
            "engine_scorecards": self.engine_scorecards,
            "marketing_metrics": self.marketing_metrics(),
        }


# Composite weighting — recall/precision dominate; framework detection +
# FP-cleanliness round it out.
_W = {"recall": 0.35, "precision": 0.30, "fp": 0.20, "confidence": 0.15}


def build_coverage_report(
    validations: list[TargetValidation],
) -> CoverageReport:
    prec = build_precision_report(validations)
    rec = build_recall_report(validations)
    fw_cards = build_framework_scorecards(validations)
    eng_cards = build_engine_scorecards(validations)

    # Framework-detection accuracy across framework targets.
    fw_targets = [tv for tv in validations if tv.framework]
    fw_correct = sum(1 for tv in fw_targets if tv.framework_correct)
    confidence_quality = (fw_correct / len(fw_targets) * 100
                          if fw_targets else 100.0)

    precision_score = prec.precision * 100
    recall_score = rec.recall * 100
    coverage_score = rec.coverage_pct
    # FP score: 100 when no FPs; decays with FP count relative to TP.
    total_signal = prec.true_positives + prec.false_positives
    fp_score = (prec.true_positives / total_signal * 100
                if total_signal else 100.0)

    overall = (
        _W["recall"] * recall_score
        + _W["precision"] * precision_score
        + _W["fp"] * fp_score
        + _W["confidence"] * confidence_quality
    )

    quality = QualityScore(
        coverage_score=coverage_score,
        precision_score=precision_score,
        recall_score=recall_score,
        confidence_quality_score=confidence_quality,
        false_positive_score=fp_score,
        overall=overall,
    )

    return CoverageReport(
        quality=quality,
        precision=prec.to_dict(),
        recall=rec.to_dict(),
        framework_scorecards={k: v.to_dict() for k, v in fw_cards.items()},
        engine_scorecards={k: v.to_dict() for k, v in eng_cards.items()},
        targets_total=len(validations),
        targets_passed=sum(1 for tv in validations if tv.passed),
    )
