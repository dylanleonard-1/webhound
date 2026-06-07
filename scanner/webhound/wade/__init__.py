# WebHound — scanner/webhound/wade/__init__.py
# WADE: Website Anomaly Detection Engine — public surface.

from .anomaly_scorer import AnomalyScorer, BASE_SCORES, ScoredAnomaly
from .baseline_builder import BaselineBuilder, PageSnapshot, SiteBaseline
from .baseline_store import BaselineMetadata, BaselineStore
from .change_classifier import ChangeAssessment, ChangeClassifier
from .change_types import ChangeBand, WadeChangeType, WadeConfidence
from .classifier import Classifier
from .confidence import (
    EVIDENCE_WEIGHTS,
    adjust_findings_confidence,
    compute_confidence,
    confidence_level,
)
from .context_engine import CONTEXT_WEIGHTS, ContextEngine, PageContext
from .diff_engine import DIFF_SEVERITY, DiffEngine, DiffItem, DiffType
from .suppression import SuppressionDecision, decide, should_suppress
from .timeline import ChangeRecord, ChangeTimeline, change_key, update_timeline
from .vendor_intel import VendorIntel, VendorVerdict

__all__ = [
    # baseline
    "BaselineBuilder",
    "PageSnapshot",
    "SiteBaseline",
    # baseline_store
    "BaselineStore",
    "BaselineMetadata",
    # diff
    "DiffEngine",
    "DiffItem",
    "DiffType",
    "DIFF_SEVERITY",
    # context
    "ContextEngine",
    "PageContext",
    "CONTEXT_WEIGHTS",
    # scoring
    "AnomalyScorer",
    "ScoredAnomaly",
    "BASE_SCORES",
    # classification
    "Classifier",
    # confidence
    "compute_confidence",
    "adjust_findings_confidence",
    "confidence_level",
    "EVIDENCE_WEIGHTS",
    # WADE 2.0 intelligence
    "ChangeClassifier",
    "ChangeAssessment",
    "WadeChangeType",
    "WadeConfidence",
    "ChangeBand",
    "VendorIntel",
    "VendorVerdict",
    "SuppressionDecision",
    "decide",
    "should_suppress",
    "ChangeRecord",
    "ChangeTimeline",
    "change_key",
    "update_timeline",
]
