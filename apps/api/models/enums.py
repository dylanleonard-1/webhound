from __future__ import annotations

import enum


class VerificationStatus(str, enum.Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"
    META_TAG = "meta_tag"
    HTML_FILE = "html_file"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    MONITOR = "monitor"


class ReportFormat(str, enum.Enum):
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"
    MARKDOWN = "markdown"
    PDF = "pdf"


class ScheduleFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class NotificationType(str, enum.Enum):
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    HIGH_RISK_FINDING = "high_risk_finding"
    CRITICAL_FINDING = "critical_finding"
    WADE_ANOMALY = "wade_anomaly"
    SCHEDULE_FAILED = "schedule_failed"


class NotificationSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlanTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    SHIELD = "shield"
    ENTERPRISE = "enterprise"


class AdminRole(str, enum.Enum):
    """Internal-platform RBAC roles for the /control command center.

    Ordered low → high privilege via ROLE_RANK below. NONE means no internal
    access at all (the default for every customer account).
    """
    NONE = "none"
    READ_ONLY = "read_only"
    BILLING = "billing"
    SUPPORT = "support"
    DEVELOPER = "developer"
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


# Privilege ranking — higher = more access. require_admin(min_role) compares
# against this, so SUPER_ADMIN implicitly satisfies every check.
ROLE_RANK: dict[AdminRole, int] = {
    AdminRole.NONE: 0,
    AdminRole.READ_ONLY: 10,
    AdminRole.BILLING: 20,
    AdminRole.SUPPORT: 20,
    AdminRole.DEVELOPER: 20,
    AdminRole.ANALYST: 30,
    AdminRole.ADMIN: 90,
    AdminRole.SUPER_ADMIN: 100,
}


class AlertSeverity(str, enum.Enum):
    """SOC alert severity, low → high. Ranked in ALERT_SEVERITY_RANK."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


ALERT_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 10, "medium": 20, "high": 30, "critical": 40,
}


class AlertStatus(str, enum.Enum):
    """Lifecycle of a SOC alert."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class SubscriptionStatus(str, enum.Enum):
    """Mirrors Stripe's subscription status values."""
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    PAUSED = "paused"
