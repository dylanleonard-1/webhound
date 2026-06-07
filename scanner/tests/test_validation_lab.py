# WebHound — tests/test_validation_lab.py
# Phase-12 Task 11: the automated validation pipeline. Runs the REAL
# scanner against a representative ground-truth subset and exercises the
# precision/recall/scorecard/quality/regression math.
#
# The full 24-target lab is available via validation.run_targets; here
# we scan a representative subset to keep the unit-test fast while still
# proving the pipeline end-to-end against the real engines.

from __future__ import annotations

import pytest

from validation import (
    ALL_TARGETS,
    CLEAN_TARGETS,
    COMPROMISED_TARGETS,
    VULNERABLE_TARGETS,
    TargetValidation,
    build_coverage_report,
    build_engine_scorecards,
    build_framework_scorecards,
    build_precision_report,
    build_recall_report,
    evaluate_regression,
    validate_run,
)
from validation.benchmark_runner import run_targets
from validation.finding_validator import FindingOutcome
from validation.ground_truth import ExpectedFinding


# ---------------------------------------------------------------------------
# Ground truth sanity
# ---------------------------------------------------------------------------


def test_ground_truth_covers_all_platforms() -> None:
    frameworks = {t.framework for t in CLEAN_TARGETS}
    assert {"WordPress", "Shopify", "Wix", "Webflow", "Next.js",
            "React", "Vue", "Angular"} <= frameworks


def test_categories_present() -> None:
    cats = {t.category for t in ALL_TARGETS}
    assert cats == {"clean", "vulnerable", "compromised"}


# ---------------------------------------------------------------------------
# Real-scanner pipeline (representative subset)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_clean_sites_detect_framework_no_false_positives() -> None:
    run = await run_targets(CLEAN_TARGETS)
    vals = validate_run(run)
    for tv in vals:
        # Every clean framework site must be correctly identified...
        assert tv.framework_correct, (
            f"{tv.target_name}: detected {tv.framework_detected}, "
            f"expected {tv.framework}")
        # ...and produce no false positives against the FP guards.
        assert tv.fp == 0, f"{tv.target_name} had {tv.fp} false positives"


@pytest.mark.anyio
async def test_vulnerable_sites_detected() -> None:
    run = await run_targets(VULNERABLE_TARGETS)
    vals = validate_run(run)
    for tv in vals:
        assert tv.fn == 0, (
            f"{tv.target_name} missed: "
            f"{[o.expected.title_substring for o in tv.false_negatives]}")


@pytest.mark.anyio
async def test_compromised_site_detected() -> None:
    run = await run_targets(COMPROMISED_TARGETS)
    vals = validate_run(run)
    for tv in vals:
        assert tv.tp >= 1
        assert tv.fn == 0


@pytest.mark.anyio
async def test_full_quality_score_is_strong() -> None:
    run = await run_targets(ALL_TARGETS)
    vals = validate_run(run)
    report = build_coverage_report(vals)
    q = report.quality
    # No false positives against any FP guard.
    assert report.precision["false_positives"] == 0
    assert q.precision_score == 100.0
    # Strong overall.
    assert q.overall >= 80.0
    # Marketing metrics shape.
    mm = report.marketing_metrics()
    assert "coverage_pct" in mm
    assert "framework_coverage" in mm


@pytest.mark.anyio
async def test_regression_gate_passes_on_clean_run() -> None:
    run = await run_targets(ALL_TARGETS)
    res = evaluate_regression(run, baseline_quality=None)
    assert res.passed is True
    assert res.overall_quality >= 60.0


# ---------------------------------------------------------------------------
# Reporting math on synthetic validations (fast, deterministic)
# ---------------------------------------------------------------------------


def _tv(name, framework, tp=0, fn=0, fp=0, fw_correct=True,
        passed_risk=True) -> TargetValidation:
    tv = TargetValidation(target_name=name, category="clean",
                          framework=framework,
                          framework_detected=framework if fw_correct else "x",
                          framework_correct=fw_correct,
                          risk_in_range=passed_risk)
    for i in range(tp):
        tv.true_positives.append(FindingOutcome(
            ExpectedFinding("security_headers", f"t{i}"), True))
    for i in range(fn):
        tv.false_negatives.append(FindingOutcome(
            ExpectedFinding("cookie_scanner", f"m{i}"), False))
    for i in range(fp):
        tv.false_positives.append({"engine": "threat_intel",
                                   "title": f"fp{i}"})
    return tv


def test_precision_recall_math() -> None:
    vals = [_tv("a", "WordPress", tp=3, fn=1, fp=1)]
    prec = build_precision_report(vals)
    rec = build_recall_report(vals)
    assert prec.precision == 0.75          # 3 / (3+1)
    assert rec.recall == 0.75              # 3 / (3+1)
    assert rec.coverage_pct == 75.0
    # FP analysis attributes to the right engine.
    fa = prec.false_positive_analysis()
    assert fa["total_false_positives"] == 1
    assert fa["by_engine"]["threat_intel"] == 1


def test_framework_and_engine_scorecards() -> None:
    vals = [
        _tv("wp1", "WordPress", tp=2, fn=0),
        _tv("wp2", "WordPress", tp=1, fn=1, fw_correct=False),
    ]
    fw = build_framework_scorecards(vals)
    wp = fw["WordPress"]
    assert wp.targets == 2
    assert wp.detection_rate == 0.5        # 1 of 2 correctly identified
    assert wp.recall == 0.75               # 3 tp / 4
    eng = build_engine_scorecards(vals)
    assert eng["security_headers"].tp == 3
    assert eng["cookie_scanner"].fn == 1


def test_quality_score_components() -> None:
    vals = [_tv("a", "WordPress", tp=4, fn=0, fp=0)]
    report = build_coverage_report(vals)
    q = report.quality
    assert q.recall_score == 100.0
    assert q.precision_score == 100.0
    assert q.false_positive_score == 100.0
    assert q.confidence_quality_score == 100.0
    assert q.overall == 100.0


def test_regression_fails_on_false_positives() -> None:
    vals_run = type("R", (), {"runs": []})()
    # Build a synthetic BenchmarkRun-like object validate_run won't see;
    # instead exercise evaluate_regression via a monkeypatched validate.
    from validation import regression_runner
    bad = [_tv("a", "WordPress", tp=2, fp=3)]
    orig = regression_runner.validate_run
    regression_runner.validate_run = lambda _run: bad
    try:
        res = regression_runner.evaluate_regression(vals_run)
    finally:
        regression_runner.validate_run = orig
    assert res.passed is False
    assert any("false positive" in r for r in res.reasons)


def test_regression_passes_when_quality_holds() -> None:
    from validation import regression_runner
    good = [_tv("a", "WordPress", tp=4)]
    orig = regression_runner.validate_run
    regression_runner.validate_run = lambda _run: good
    try:
        res = regression_runner.evaluate_regression(
            type("R", (), {"runs": []})(), baseline_quality=100.0)
    finally:
        regression_runner.validate_run = orig
    # tp-only run scores 100; baseline 100 → delta 0 → within tolerance.
    assert res.passed is True


def test_regression_fails_when_quality_drops_below_baseline() -> None:
    from validation import regression_runner
    # 3 tp / 1 fn → recall 75; with no FPs precision 100, fw 100, fp 100.
    weaker = [_tv("a", "WordPress", tp=3, fn=1)]
    orig = regression_runner.validate_run
    regression_runner.validate_run = lambda _run: weaker
    try:
        res = regression_runner.evaluate_regression(
            type("R", (), {"runs": []})(), baseline_quality=99.0)
    finally:
        regression_runner.validate_run = orig
    assert res.passed is False
    assert any("dropped" in r for r in res.reasons)
