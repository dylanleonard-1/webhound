"""Import all models so SQLAlchemy registers them with Base.metadata."""
from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import (
    ReportFormat,
    ScheduleFrequency,
    ScanProfile,
    ScanStatus,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website

__all__ = [
    "User",
    "Website",
    "DomainVerification",
    "ScanJob",
    "ScanResultRecord",
    "FindingRecord",
    "GroupedFindingRecord",
    "EngineDiagnosticRecord",
    "BaselineRecord",
    "ReportRecord",
    "ScanSchedule",
    "VerificationStatus",
    "VerificationMethod",
    "ScanStatus",
    "ScanProfile",
    "ReportFormat",
    "ScheduleFrequency",
]
