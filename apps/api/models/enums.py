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
