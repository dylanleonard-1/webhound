# WebHound — scanner/validation/precision_report.py
# Phase-12 Tasks 2 + 6: precision (TP / (TP+FP)) overall, per engine,
# per framework, plus a false-positive analysis. Pure aggregation over
# TargetValidation records.

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from validation.finding_validator import TargetValidation


def _precision(tp: int, fp: int) -> float:
    return round(tp / (tp + fp), 4) if (tp + fp) else 1.0


@dataclass
class PrecisionReport:
    true_positives: int = 0
    false_positives: int = 0
    per_engine: dict[str, dict[str, int]] = field(default_factory=dict)
    per_framework: dict[str, dict[str, int]] = field(default_factory=dict)
    false_positive_catalog: list[dict[str, Any]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return _precision(self.true_positives, self.false_positives)

    def engine_precision(self, engine: str) -> float:
        d = self.per_engine.get(engine, {})
        return _precision(d.get("tp", 0), d.get("fp", 0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": self.precision,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "per_engine": {
                e: {**c, "precision": _precision(c.get("tp", 0),
                                                 c.get("fp", 0))}
                for e, c in sorted(self.per_engine.items())
            },
            "per_framework": {
                f: {**c, "precision": _precision(c.get("tp", 0),
                                                 c.get("fp", 0))}
                for f, c in sorted(self.per_framework.items())
            },
            "false_positive_analysis": self.false_positive_analysis(),
        }

    def false_positive_analysis(self) -> dict[str, Any]:
        """Task 6: most common FPs + responsible engine + frequency +
        framework + a tuning hint."""
        by_engine: dict[str, int] = defaultdict(int)
        by_signature: dict[tuple[str, str], int] = defaultdict(int)
        by_framework: dict[str, int] = defaultdict(int)
        for fp in self.false_positive_catalog:
            by_engine[fp["engine"]] += 1
            by_signature[(fp["engine"], fp.get("title", ""))] += 1
            if fp.get("framework"):
                by_framework[fp["framework"]] += 1
        top = sorted(by_signature.items(), key=lambda kv: kv[1],
                     reverse=True)[:10]
        return {
            "total_false_positives": len(self.false_positive_catalog),
            "by_engine": dict(sorted(by_engine.items(),
                                     key=lambda kv: kv[1], reverse=True)),
            "by_framework": dict(by_framework),
            "most_common": [
                {"engine": eng, "title": title, "count": n,
                 "tuning_hint": _tuning_hint(eng)}
                for (eng, title), n in top
            ],
        }


def _tuning_hint(engine: str) -> str:
    return {
        "threat_intel": "tighten domain heuristics / expand benign vendor list",
        "obfuscation_detector": "raise the minified-vendor-JS suppression bar",
        "third_party_domains": "expand known-vendor allowlist",
        "security_headers": "ensure header findings stay hardening-typed",
        "injected_js": "narrow injection signature to reduce SPA noise",
    }.get(engine, "review detection signature for this engine")


def build_precision_report(
    validations: list[TargetValidation],
) -> PrecisionReport:
    rep = PrecisionReport()
    for tv in validations:
        rep.true_positives += tv.tp
        rep.false_positives += tv.fp
        # Per-engine TP.
        for o in tv.true_positives:
            d = rep.per_engine.setdefault(o.expected.engine,
                                          {"tp": 0, "fp": 0})
            d["tp"] += 1
        # Per-engine FP + catalog.
        for fp in tv.false_positives:
            d = rep.per_engine.setdefault(fp["engine"], {"tp": 0, "fp": 0})
            d["fp"] += 1
            rep.false_positive_catalog.append({**fp,
                                               "framework": tv.framework,
                                               "target": tv.target_name})
        # Per-framework.
        fw = tv.framework or "none"
        fd = rep.per_framework.setdefault(fw, {"tp": 0, "fp": 0})
        fd["tp"] += tv.tp
        fd["fp"] += tv.fp
    return rep
