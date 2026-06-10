from __future__ import annotations

import enum


class VerificationStatus(str, enum.Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    # Phase-3.2: ownership lifecycle. EXPIRED = a previously-valid proof
    # lapsed (re-verify required); REVOKED = the owner withdrew access
    # (monitoring paused). Both are treated as "not verified" by the gate.
    EXPIRED = "expired"
    REVOKED = "revoked"


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


class OrgRole(str, enum.Enum):
    """Tenant-scoped RBAC roles within a single :class:`Org`.

    Distinct from :class:`AdminRole`, which is *platform-wide* internal-SOC
    access. An ``OrgRole`` only authorises actions on the org it's attached
    to — a user can be ``OWNER`` of one org and ``VIEWER`` of another.

    Ordered low → high via ORG_ROLE_RANK below."""
    VIEWER = "viewer"       # read findings + scan results only
    BILLING = "billing"     # billing surface + read findings
    ANALYST = "analyst"     # acknowledge alerts, manage suppressions, start scans
    ADMIN = "admin"         # manage members + integrations + everything below
    OWNER = "owner"         # owner privilege, can transfer ownership


# Privilege ranking — higher = more access. has_org_role(min_role) compares
# against this so OWNER implicitly satisfies every check.
ORG_ROLE_RANK: dict[OrgRole, int] = {
    OrgRole.VIEWER: 10,
    OrgRole.BILLING: 20,
    OrgRole.ANALYST: 30,
    OrgRole.ADMIN: 80,
    OrgRole.OWNER: 100,
}


class DriftSeverity(str, enum.Enum):
    """Severity of a scan-to-scan delta (continuous-monitoring drift).

    ``NONE`` is emitted explicitly when a delta was computed but no
    meaningful change was found — so the UI can distinguish "we looked,
    nothing happened" from "we haven't looked yet"."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
