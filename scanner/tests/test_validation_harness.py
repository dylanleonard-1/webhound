# WebHound — scanner/tests/test_validation_harness.py
# Phase 9B: Unit tests for the validation harness itself.
# Tests the data model and mock-based reporting — no live network.

from __future__ import annotations

import pytest

from validation.harness import (
    ValidationTarget,
    ValidationRun,
    ValidationFinding,
    ValidationEvidence,
    ValidationReport,
    ValidationStatus,
    TargetCategory,
    SAFE_TARGET_MATRIX,
)


# ---------------------------------------------------------------------------
# ValidationTarget
# ---------------------------------------------------------------------------

class TestValidationTarget:
    def _target(self, **kwargs) -> ValidationTarget:
        defaults = dict(
            url="https://example.com/",
            name="test",
            category=TargetCategory.STATIC,
            provider="self",
            platform="html",
            expected_finding_types=["missing_csp"],
            expected_absent_types=[],
            known_constraints=[],
        )
        defaults.update(kwargs)
        return ValidationTarget(**defaults)

    def test_target_creation(self):
        t = self._target()
        assert t.url == "https://example.com/"

    def test_safe_for_live_defaults_true(self):
        t = self._target()
        assert t.safe_for_live is True

    def test_target_has_category(self):
        t = self._target(category=TargetCategory.CLOUDFLARE)
        assert t.category == TargetCategory.CLOUDFLARE


# ---------------------------------------------------------------------------
# ValidationFinding
# ---------------------------------------------------------------------------

class TestValidationFinding:
    def _finding(self, status: ValidationStatus = ValidationStatus.PASSED) -> ValidationFinding:
        return ValidationFinding(
            target_url="https://example.com/",
            engine="security_headers",
            finding_type="missing_csp",
            title="Missing CSP",
            severity="medium",
            confidence=0.95,
            status=status,
            expected=True,
        )

    def test_finding_status_passed(self):
        f = self._finding(ValidationStatus.PASSED)
        assert f.status == ValidationStatus.PASSED

    def test_finding_status_fp(self):
        f = self._finding(ValidationStatus.FP)
        assert f.status == ValidationStatus.FP


# ---------------------------------------------------------------------------
# ValidationRun
# ---------------------------------------------------------------------------

class TestValidationRun:
    def _target(self) -> ValidationTarget:
        return ValidationTarget(
            url="https://example.com/",
            name="test",
            category=TargetCategory.STATIC,
            provider="self",
            platform="html",
            expected_finding_types=[],
            expected_absent_types=[],
            known_constraints=[],
        )

    def _run_with(self, statuses: list[ValidationStatus]) -> ValidationRun:
        target = self._target()
        run = ValidationRun(target=target)
        for i, status in enumerate(statuses):
            run.findings.append(ValidationFinding(
                target_url=target.url,
                engine="headers",
                finding_type=f"finding_{i}",
                title=f"Finding {i}",
                severity="medium",
                confidence=0.9,
                status=status,
                expected=True,
            ))
        run.finish()
        return run

    def test_tp_count(self):
        run = self._run_with([ValidationStatus.PASSED, ValidationStatus.PASSED, ValidationStatus.FP])
        assert run.tp_count == 2

    def test_fp_count(self):
        run = self._run_with([ValidationStatus.FP, ValidationStatus.PASSED])
        assert run.fp_count == 1

    def test_fn_count(self):
        run = self._run_with([ValidationStatus.FAILED, ValidationStatus.PASSED])
        assert run.fn_count == 1

    def test_uncertain_count(self):
        run = self._run_with([ValidationStatus.UNCERTAIN])
        assert run.uncertain_count == 1

    def test_completed_at_set_after_finish(self):
        run = ValidationRun(target=self._target())
        run.finish()
        assert run.completed_at is not None

    def test_live_scan_defaults_false(self):
        run = ValidationRun(target=self._target())
        assert run.live_scan is False


# ---------------------------------------------------------------------------
# ValidationReport
# ---------------------------------------------------------------------------

class TestValidationReport:
    def _report_with(self, tp: int, fp: int, fn: int) -> ValidationReport:
        target = ValidationTarget(
            url="https://example.com/",
            name="test",
            category=TargetCategory.STATIC,
            provider="self",
            platform="html",
            expected_finding_types=[],
            expected_absent_types=[],
            known_constraints=[],
        )
        findings = (
            [ValidationFinding("https://example.com/", "e", "t", "T", "medium", 0.9, ValidationStatus.PASSED, True)] * tp
            + [ValidationFinding("https://example.com/", "e", "t", "T", "medium", 0.9, ValidationStatus.FP, False)] * fp
            + [ValidationFinding("https://example.com/", "e", "t", "T", "medium", 0.9, ValidationStatus.FAILED, True)] * fn
        )
        mock_results = {"https://example.com/": findings}
        return ValidationReport.run_mock([target], mock_results)

    def test_total_tp(self):
        report = self._report_with(3, 1, 1)
        assert report.total_tp == 3

    def test_total_fp(self):
        report = self._report_with(3, 1, 1)
        assert report.total_fp == 1

    def test_total_fn(self):
        report = self._report_with(3, 1, 1)
        assert report.total_fn == 1

    def test_precision(self):
        report = self._report_with(3, 1, 0)
        assert abs(report.precision - 0.75) < 0.01

    def test_recall(self):
        report = self._report_with(3, 0, 1)
        assert abs(report.recall - 0.75) < 0.01

    def test_perfect_precision(self):
        report = self._report_with(5, 0, 0)
        assert report.precision == 1.0

    def test_zero_tp_zero_precision(self):
        report = self._report_with(0, 2, 0)
        assert report.precision == 0.0

    def test_summary_keys(self):
        report = self._report_with(2, 1, 1)
        summary = report.summary()
        assert "runs" in summary
        assert "precision" in summary
        assert "recall" in summary

    def test_run_mock_builds_runs(self):
        target = ValidationTarget(
            url="https://t1.example.com/",
            name="t1",
            category=TargetCategory.STATIC,
            provider="x",
            platform="html",
            expected_finding_types=[],
            expected_absent_types=[],
            known_constraints=[],
        )
        report = ValidationReport.run_mock([target], {})
        assert len(report.runs) == 1
        assert report.runs[0].live_scan is False


# ---------------------------------------------------------------------------
# SAFE_TARGET_MATRIX integrity
# ---------------------------------------------------------------------------

class TestSafeTargetMatrix:
    def test_matrix_not_empty(self):
        assert len(SAFE_TARGET_MATRIX) > 0

    def test_all_targets_have_url(self):
        for t in SAFE_TARGET_MATRIX:
            assert t.url.startswith("http")

    def test_all_targets_have_name(self):
        for t in SAFE_TARGET_MATRIX:
            assert t.name

    def test_no_arbitrary_third_party_sites(self):
        # All URLs must be subdomains of known, consented root domains
        approved_roots = {
            "badssl.com", "vulnweb.com", "testfire.net",
            "webhoundsecurity.com", "cloudflare.com",
        }
        for t in SAFE_TARGET_MATRIX:
            from urllib.parse import urlparse
            domain = urlparse(t.url).netloc.removeprefix("www.")
            parts = domain.split(".")
            base = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            assert base in approved_roots, f"Unapproved domain in target matrix: {domain}"

    def test_all_targets_have_category(self):
        for t in SAFE_TARGET_MATRIX:
            assert isinstance(t.category, TargetCategory)
