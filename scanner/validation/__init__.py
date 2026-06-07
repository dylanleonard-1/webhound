# WebHound — scanner/validation/__init__.py
# Phase-12 scanner validation lab & accuracy framework.

from validation.coverage_report import (
    CoverageReport,
    QualityScore,
    build_coverage_report,
)
from validation.finding_validator import (
    TargetValidation,
    validate_run,
    validate_target,
)
from validation.framework_scorecard import (
    EngineScorecard,
    FrameworkScorecard,
    build_engine_scorecards,
    build_framework_scorecards,
)
from validation.ground_truth import (
    ALL_TARGETS,
    CLEAN_TARGETS,
    COMPROMISED_TARGETS,
    VULNERABLE_TARGETS,
    ExpectedFinding,
    GroundTruthTarget,
)
from validation.precision_report import PrecisionReport, build_precision_report
from validation.recall_report import RecallReport, build_recall_report
from validation.regression_runner import (
    RegressionResult,
    evaluate_regression,
)

__all__ = [
    "CoverageReport", "QualityScore", "build_coverage_report",
    "TargetValidation", "validate_run", "validate_target",
    "EngineScorecard", "FrameworkScorecard", "build_engine_scorecards",
    "build_framework_scorecards", "ALL_TARGETS", "CLEAN_TARGETS",
    "COMPROMISED_TARGETS", "VULNERABLE_TARGETS", "ExpectedFinding",
    "GroundTruthTarget", "PrecisionReport", "build_precision_report",
    "RecallReport", "build_recall_report", "RegressionResult",
    "evaluate_regression",
]
