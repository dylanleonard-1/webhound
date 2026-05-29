# WebHound — webhound/reporting/production_readiness.py
# Phase-5I: production readiness scoring + final gap report.
#
# Reads every audit signal the scanner now emits + the structured
# benchmark results (when supplied) and rolls up into a single 0-100
# readiness score with itemised dimension breakdowns. Output is the
# canonical "is the scanner ready for production?" answer the
# operator + dashboard render in one place.
#
# Pure-function — no I/O. Takes a ScanResult (or a list of
# BenchmarkResults) and returns a ProductionReadinessReport.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from webhound.benchmark.harness import BenchmarkResult
from webhound.models.scan_result import ScanResult


# Per-dimension weights. Each dimension contributes 0-100 of its
# own score; the rollup is a weighted average. Weights are calibrated
# so the most operationally important signals (FP rate, threat-intel
# coverage, evidence quality) carry the most weight.
_DIMENSION_WEIGHTS: dict[str, float] = {
    "evidence_quality":      0.20,
    "threat_intel_coverage": 0.20,
    "benchmark_recall":      0.15,
    "benchmark_precision":   0.15,
    "discovery_coverage":    0.10,
    "engine_reliability":    0.10,
    "dashboard_parity":      0.05,
    "wade_review_signal":    0.05,
}


@dataclass
class DimensionScore:
    name: str
    score: float            # 0-100
    detail: str
    raw_inputs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 2),
            "detail": self.detail,
            "raw_inputs": self.raw_inputs,
        }


@dataclass
class ProductionReadinessReport:
    overall_score: float = 0.0
    grade: str = "ungraded"
    ready: bool = False
    dimensions: list[DimensionScore] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "grade": self.grade,
            "ready": self.ready,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "gaps": list(self.gaps),
        }


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def score_scan(
    result: ScanResult,
    *,
    benchmarks: Iterable[BenchmarkResult] | None = None,
) -> ProductionReadinessReport:
    """Score one scan's production readiness.

    ``benchmarks`` are optional; when supplied, precision/recall
    dimensions are populated from them. When omitted, those
    dimensions score 100 (no signal = no penalty)."""
    dims: list[DimensionScore] = []
    gaps: list[str] = []
    meta = result.metadata or {}

    dims.append(_score_evidence_quality(meta, gaps))
    dims.append(_score_threat_intel_coverage(meta, gaps))
    dims.append(_score_discovery_coverage(meta, gaps))
    dims.append(_score_engine_reliability(result, gaps))
    dims.append(_score_dashboard_parity(meta, gaps))
    dims.append(_score_wade_review(meta, gaps))
    bm_list = list(benchmarks or [])
    dims.append(_score_benchmark_recall(bm_list, gaps))
    dims.append(_score_benchmark_precision(bm_list, gaps))

    weighted_sum = 0.0
    weight_total = 0.0
    for d in dims:
        w = _DIMENSION_WEIGHTS.get(d.name, 0.0)
        weighted_sum += d.score * w
        weight_total += w
    overall = (weighted_sum / weight_total) if weight_total else 0.0
    report = ProductionReadinessReport(
        overall_score=overall,
        grade=_grade(overall),
        ready=overall >= 80.0,
        dimensions=dims,
        gaps=gaps,
    )
    return report


def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ---------------------------------------------------------------------------
# Individual dimension scorers
# ---------------------------------------------------------------------------


def _score_evidence_quality(
    meta: dict[str, Any], gaps: list[str],
) -> DimensionScore:
    eq = meta.get("evidence_quality") or {}
    ratio = float(eq.get("completeness_ratio") or 1.0)
    score = round(ratio * 100, 2)
    if ratio < 0.95 and eq.get("incomplete_count"):
        gaps.append(
            f"Evidence quality: {eq['incomplete_count']} finding(s) "
            "missing rationale or location."
        )
    return DimensionScore(
        name="evidence_quality",
        score=score,
        detail=f"Completeness {round(ratio * 100, 1)}%",
        raw_inputs=eq,
    )


def _score_threat_intel_coverage(
    meta: dict[str, Any], gaps: list[str],
) -> DimensionScore:
    cov = meta.get("threat_intel_coverage") or {}
    ratio = float(cov.get("coverage_ratio") or 1.0)
    score = round(ratio * 100, 2)
    if cov.get("has_coverage_gap"):
        gaps.append(
            f"Threat-intel: {len(cov.get('unclassified_hosts') or [])} "
            "host(s) unclassified."
        )
    return DimensionScore(
        name="threat_intel_coverage",
        score=score,
        detail=f"Coverage {round(ratio * 100, 1)}%",
        raw_inputs=cov,
    )


def _score_discovery_coverage(
    meta: dict[str, Any], gaps: list[str],
) -> DimensionScore:
    """Surface area discovered relative to expectation. We don't have
    a 'ground truth' surface count, so we proxy via the number of
    discovery sources actively contributing to the inventory."""
    cov = meta.get("threat_intel_coverage") or {}
    sources = cov.get("per_source_count") or {}
    distinct_sources = len(sources)
    # 6 canonical sources: static_html / js_literal / browser /
    # iframe / redirect / csp. ≥4 = full coverage; <2 = sparse.
    score = min(100.0, distinct_sources * 25.0)
    if distinct_sources < 3:
        gaps.append(
            "Discovery coverage: only "
            f"{distinct_sources} source(s) contributed. Browser pass "
            "may be off, or page lacks JS / CSP."
        )
    return DimensionScore(
        name="discovery_coverage",
        score=score,
        detail=f"{distinct_sources} active discovery source(s)",
        raw_inputs={"per_source_count": sources},
    )


def _score_engine_reliability(
    result: ScanResult, gaps: list[str],
) -> DimensionScore:
    """Fraction of engines that ran without error vs total engines
    run."""
    diags = getattr(result, "engine_diagnostics", None) or []
    if not diags:
        return DimensionScore(
            name="engine_reliability",
            score=100.0,
            detail="No diagnostics — assuming clean.",
        )
    errored = [d for d in diags if getattr(d, "status", None)
                and str(d.status).lower() in ("failed", "error")]
    total = len(diags)
    score = round((1 - (len(errored) / total)) * 100, 2)
    if errored:
        gaps.append(
            f"Engine reliability: {len(errored)} engine(s) failed "
            "during this scan."
        )
    return DimensionScore(
        name="engine_reliability",
        score=score,
        detail=f"{total - len(errored)}/{total} engines clean",
    )


def _score_dashboard_parity(
    meta: dict[str, Any], gaps: list[str],
) -> DimensionScore:
    """Does the scan emit every v4 field the dashboard expects?
    Each present-and-non-null field is worth points."""
    expected = (
        "compliance", "evidence_graph", "asset_map",
        "correlated_chains", "threat_intel_coverage",
        "evidence_quality", "wade_quality_review", "browser_pass",
    )
    present = sum(1 for k in expected if meta.get(k) is not None)
    score = round((present / len(expected)) * 100, 2)
    if present < len(expected):
        missing = [k for k in expected if meta.get(k) is None]
        gaps.append(
            "Dashboard parity: missing scanner_metadata key(s): "
            + ", ".join(missing)
        )
    return DimensionScore(
        name="dashboard_parity",
        score=score,
        detail=f"{present}/{len(expected)} v4 fields present",
    )


def _score_wade_review(
    meta: dict[str, Any], gaps: list[str],
) -> DimensionScore:
    """WADE flagged possible FPs or weak findings? Each note costs
    points but doesn't zero the dimension — the review is advisory."""
    review = meta.get("wade_quality_review") or {}
    note_count = int(review.get("note_count") or 0)
    total = int(review.get("total_findings_reviewed") or 0)
    if total == 0:
        return DimensionScore(
            name="wade_review_signal",
            score=100.0,
            detail="No findings to review.",
        )
    # 5 notes per 100 findings is concerning; ≥10 is bad.
    ratio = note_count / total
    score = round(max(0.0, 100 - ratio * 400), 2)
    if note_count >= 3:
        gaps.append(
            f"WADE flagged {note_count} possible quality issue(s) "
            f"across {total} finding(s)."
        )
    return DimensionScore(
        name="wade_review_signal",
        score=score,
        detail=f"{note_count} advisory note(s) for {total} finding(s)",
    )


def _score_benchmark_recall(
    benchmarks: list[BenchmarkResult], gaps: list[str],
) -> DimensionScore:
    if not benchmarks:
        return DimensionScore(
            name="benchmark_recall",
            score=100.0,
            detail="No benchmarks supplied.",
        )
    avg = sum(b.recall for b in benchmarks) / len(benchmarks)
    score = round(avg * 100, 2)
    if score < 80:
        gaps.append(
            f"Benchmark recall: average {round(avg * 100, 1)}% — "
            "scanner missed expected findings on multiple sites."
        )
    return DimensionScore(
        name="benchmark_recall",
        score=score,
        detail=f"Avg recall {round(avg * 100, 1)}%",
    )


def _score_benchmark_precision(
    benchmarks: list[BenchmarkResult], gaps: list[str],
) -> DimensionScore:
    if not benchmarks:
        return DimensionScore(
            name="benchmark_precision",
            score=100.0,
            detail="No benchmarks supplied.",
        )
    avg = sum(b.precision for b in benchmarks) / len(benchmarks)
    score = round(avg * 100, 2)
    if score < 80:
        gaps.append(
            f"Benchmark precision: average {round(avg * 100, 1)}% — "
            "false positives appeared on multiple sites."
        )
    return DimensionScore(
        name="benchmark_precision",
        score=score,
        detail=f"Avg precision {round(avg * 100, 1)}%",
    )
