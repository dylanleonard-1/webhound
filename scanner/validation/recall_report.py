# WebHound — scanner/validation/recall_report.py
# Phase-12 Tasks 3 + 7: recall (TP / (TP+FN)) + coverage % overall and
# per framework, plus false-negative analysis (what we missed). Pure.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from validation.finding_validator import TargetValidation


def _recall(tp: int, fn: int) -> float:
    return round(tp / (tp + fn), 4) if (tp + fn) else 1.0


@dataclass
class RecallReport:
    detected: int = 0                 # known findings detected (TP)
    missed: int = 0                   # known findings missed (FN)
    per_framework: dict[str, dict[str, int]] = field(default_factory=dict)
    per_engine: dict[str, dict[str, int]] = field(default_factory=dict)
    missed_catalog: list[dict[str, Any]] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return _recall(self.detected, self.missed)

    @property
    def coverage_pct(self) -> float:
        return round(self.recall * 100, 1)

    def framework_recall(self, framework: str) -> float:
        d = self.per_framework.get(framework, {})
        return _recall(d.get("tp", 0), d.get("fn", 0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "recall": self.recall,
            "coverage_pct": self.coverage_pct,
            "detected": self.detected,
            "missed": self.missed,
            "per_framework": {
                f: {**c, "recall": _recall(c.get("tp", 0), c.get("fn", 0)),
                    "coverage_pct": round(
                        _recall(c.get("tp", 0), c.get("fn", 0)) * 100, 1)}
                for f, c in sorted(self.per_framework.items())
            },
            "per_engine": {
                e: {**c, "recall": _recall(c.get("tp", 0), c.get("fn", 0))}
                for e, c in sorted(self.per_engine.items())
            },
            "false_negative_analysis": {
                "total_missed": self.missed,
                "missed_findings": self.missed_catalog[:50],
            },
        }


def build_recall_report(validations: list[TargetValidation]) -> RecallReport:
    rep = RecallReport()
    for tv in validations:
        rep.detected += tv.tp
        rep.missed += tv.fn
        fw = tv.framework or "none"
        fd = rep.per_framework.setdefault(fw, {"tp": 0, "fn": 0})
        fd["tp"] += tv.tp
        fd["fn"] += tv.fn
        for o in tv.true_positives:
            d = rep.per_engine.setdefault(o.expected.engine,
                                          {"tp": 0, "fn": 0})
            d["tp"] += 1
        for o in tv.false_negatives:
            d = rep.per_engine.setdefault(o.expected.engine,
                                          {"tp": 0, "fn": 0})
            d["fn"] += 1
            rep.missed_catalog.append({
                "target": tv.target_name,
                "framework": tv.framework,
                "engine": o.expected.engine,
                "title": o.expected.title_substring,
            })
    return rep
