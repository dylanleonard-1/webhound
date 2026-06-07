# WebHound — scanner/validation/framework_scorecard.py
# Phase-12 Tasks 4 + 5: per-framework and per-engine scorecards.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from validation.finding_validator import TargetValidation


def _ratio(num: int, denom: int) -> float:
    return round(num / denom, 4) if denom else 1.0


@dataclass
class FrameworkScorecard:
    framework: str
    targets: int = 0
    detection_correct: int = 0        # framework correctly identified
    tp: int = 0
    fn: int = 0
    fp: int = 0
    passed_targets: int = 0

    @property
    def detection_rate(self) -> float:
        return _ratio(self.detection_correct, self.targets)

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def precision(self) -> float:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def pass_rate(self) -> float:
        return _ratio(self.passed_targets, self.targets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "targets": self.targets,
            "framework_detection_rate": self.detection_rate,
            "precision": self.precision,
            "recall": self.recall,
            "coverage_pct": round(self.recall * 100, 1),
            "pass_rate": self.pass_rate,
        }


@dataclass
class EngineScorecard:
    engine: str
    tp: int = 0
    fn: int = 0
    fp: int = 0

    @property
    def precision(self) -> float:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.tp + self.fn)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "true_positives": self.tp,
            "false_negatives": self.fn,
            "false_positives": self.fp,
            "precision": self.precision,
            "recall": self.recall,
        }


def build_framework_scorecards(
    validations: list[TargetValidation],
) -> dict[str, FrameworkScorecard]:
    cards: dict[str, FrameworkScorecard] = {}
    for tv in validations:
        if not tv.framework:
            continue
        card = cards.setdefault(tv.framework,
                                FrameworkScorecard(framework=tv.framework))
        card.targets += 1
        if tv.framework_correct:
            card.detection_correct += 1
        card.tp += tv.tp
        card.fn += tv.fn
        card.fp += tv.fp
        if tv.passed:
            card.passed_targets += 1
    return cards


def build_engine_scorecards(
    validations: list[TargetValidation],
) -> dict[str, EngineScorecard]:
    cards: dict[str, EngineScorecard] = {}
    for tv in validations:
        for o in tv.true_positives:
            cards.setdefault(o.expected.engine,
                             EngineScorecard(engine=o.expected.engine)).tp += 1
        for o in tv.false_negatives:
            cards.setdefault(o.expected.engine,
                             EngineScorecard(engine=o.expected.engine)).fn += 1
        for fp in tv.false_positives:
            cards.setdefault(fp["engine"],
                             EngineScorecard(engine=fp["engine"])).fp += 1
    return cards
