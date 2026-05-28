"""Import all models so SQLAlchemy registers them with Base.metadata."""
from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.alert import Alert, AlertComment
from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import (
    AdminRole,
    AlertSeverity,
    AlertStatus,
    NotificationSeverity,
    NotificationType,
    PlanTier,
    ReportFormat,
    ScheduleFrequency,
    ScanProfile,
    ScanStatus,
    SubscriptionStatus,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.internal_note import InternalNote
from apps.api.models.notification import Notification
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.subscription import Subscription
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website

__all__ = [
    "User",
    "AdminAuditLog",
    "AdminRole",
    "Alert",
    "AlertComment",
    "AlertSeverity",
    "AlertStatus",
    "Website",
    "DomainVerification",
    "ScanJob",
    "ScanResultRecord",
    "FindingRecord",
    "GroupedFindingRecord",
    "EngineDiagnosticRecord",
    "InternalNote",
    "BaselineRecord",
    "ReportRecord",
    "ScanSchedule",
    "Notification",
    "Subscription",
    "VerificationStatus",
    "VerificationMethod",
    "ScanStatus",
    "ScanProfile",
    "ReportFormat",
    "ScheduleFrequency",
    "NotificationType",
    "NotificationSeverity",
    "PlanTier",
    "SubscriptionStatus",
]
