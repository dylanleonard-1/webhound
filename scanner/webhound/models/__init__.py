# WebHound — scanner/webhound/models/__init__.py
# Public surface of the models package.

from .baseline import Baseline, BaselineEntry, BaselineStatus, ResponseProfile
from .evidence import Evidence, EvidenceType
from .finding import Finding, FindingCategory, FrameworkAlignment
from .scan_result import ScanError, ScanResult, ScanStatus, SeverityBreakdown
from .severity import Severity
from .target import ScanOptions, Target, TargetScope, TLSInfo

__all__ = [
    # severity
    "Severity",
    # evidence
    "Evidence",
    "EvidenceType",
    # finding
    "Finding",
    "FindingCategory",
    "FrameworkAlignment",
    # target
    "Target",
    "TargetScope",
    "TLSInfo",
    "ScanOptions",
    # scan_result
    "ScanResult",
    "ScanStatus",
    "SeverityBreakdown",
    "ScanError",
    # baseline
    "Baseline",
    "BaselineEntry",
    "BaselineStatus",
    "ResponseProfile",
]
