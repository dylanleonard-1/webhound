"""Import all models so SQLAlchemy registers them with Base.metadata."""
from apps.api.models.abuse import AbuseFlag, IPDeviceFingerprint
from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.alert import Alert, AlertComment
from apps.api.models.baseline import BaselineRecord
from apps.api.models.deployment import Deployment
from apps.api.models.engine import EngineRegistry
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.incident import Incident, IncidentEvent
from apps.api.models.infrastructure_sample import InfrastructureSample
from apps.api.models.enums import (
    AdminRole,
    AlertSeverity,
    AlertStatus,
    DriftSeverity,
    NotificationSeverity,
    NotificationType,
    OrgRole,
    PlanTier,
    ReportFormat,
    ScheduleFrequency,
    ScanProfile,
    ScanStatus,
    SubscriptionStatus,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.org import Org, OrgMembership
from apps.api.models.scan_delta import ScanDelta
from apps.api.models.suppression import Suppression, SuppressionScope
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.internal_note import InternalNote
from apps.api.models.log_record import LogRecord
from apps.api.models.notification import Notification
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.subscription import Subscription
from apps.api.models.support_ticket import SupportTicket, SupportTicketEvent
from apps.api.models.threat_indicator import ThreatIndicator
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website
from apps.api.models.website_group import WebsiteGroup

__all__ = [
    "User",
    "WebsiteGroup",
    "AdminAuditLog",
    "AdminRole",
    "AbuseFlag",
    "Alert",
    "AlertComment",
    "AlertSeverity",
    "AlertStatus",
    "IPDeviceFingerprint",
    "Website",
    "DomainVerification",
    "ScanJob",
    "ScanResultRecord",
    "FindingRecord",
    "GroupedFindingRecord",
    "EngineDiagnosticRecord",
    "EngineRegistry",
    "Incident",
    "IncidentEvent",
    "InternalNote",
    "LogRecord",
    "BaselineRecord",
    "Deployment",
    "InfrastructureSample",
    "ReportRecord",
    "ScanSchedule",
    "Notification",
    "Subscription",
    "SupportTicket",
    "SupportTicketEvent",
    "ThreatIndicator",
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
    # Phase-4 multi-tenancy + continuous-monitoring delta
    "Org",
    "OrgMembership",
    "OrgRole",
    "ScanDelta",
    "DriftSeverity",
    "Suppression",
    "SuppressionScope",
    # Phase-3.1 provider discovery
    "ProviderProfile",
]
