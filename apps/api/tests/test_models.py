"""Model import, construction, and enum tests — no database required."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa

import apps.api.models  # noqa: F401 — ensure all models are registered
from apps.api.database import Base
from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import (
    NotificationSeverity,
    NotificationType,
    ReportFormat,
    ScheduleFrequency,
    ScanProfile,
    ScanStatus,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.notification import Notification
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website


# ---------------------------------------------------------------------------
# Enum values
# ---------------------------------------------------------------------------


class TestEnums:
    def test_verification_status_values(self):
        assert set(VerificationStatus) == {
            VerificationStatus.UNVERIFIED,
            VerificationStatus.PENDING,
            VerificationStatus.VERIFIED,
            VerificationStatus.FAILED,
        }

    def test_verification_method_values(self):
        assert set(VerificationMethod) == {
            VerificationMethod.DNS_TXT,
            VerificationMethod.META_TAG,
            VerificationMethod.HTML_FILE,
        }

    def test_scan_status_values(self):
        assert set(ScanStatus) == {
            ScanStatus.QUEUED,
            ScanStatus.RUNNING,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }

    def test_scan_profile_values(self):
        assert set(ScanProfile) == {
            ScanProfile.QUICK,
            ScanProfile.STANDARD,
            ScanProfile.DEEP,
            ScanProfile.MONITOR,
        }

    def test_report_format_values(self):
        assert set(ReportFormat) == {
            ReportFormat.JSON,
            ReportFormat.SARIF,
            ReportFormat.CSV,
            ReportFormat.MARKDOWN,
        }

    def test_enum_str_values(self):
        assert ScanStatus.QUEUED == "queued"
        assert ScanProfile.STANDARD == "standard"
        assert VerificationStatus.VERIFIED == "verified"
        assert ReportFormat.JSON == "json"


# ---------------------------------------------------------------------------
# Model table names registered with metadata
# ---------------------------------------------------------------------------


class TestMetadataRegistration:
    def test_all_tables_registered(self):
        tables = set(Base.metadata.tables.keys())
        expected = {
            "users",
            "websites",
            "domain_verifications",
            "scan_jobs",
            "scan_results",
            "findings",
            "grouped_findings",
            "engine_diagnostics",
            "baselines",
            "reports",
        }
        assert expected.issubset(tables)

    def test_table_count(self):
        assert len(Base.metadata.tables) >= 10


# ---------------------------------------------------------------------------
# Model object construction (no DB)
# ---------------------------------------------------------------------------


class TestUserConstruction:
    def test_user_default_id(self):
        u = User(email="a@example.com")
        assert u.email == "a@example.com"

    def test_user_explicit_id(self):
        uid = uuid.uuid4()
        u = User(id=uid, email="b@example.com")
        assert u.id == uid

    def test_user_is_active_default(self):
        u = User(email="c@example.com")
        assert u.is_active is True or u.is_active is None  # default applied by DB

    def test_user_nullable_password(self):
        u = User(email="d@example.com", hashed_password=None)
        assert u.hashed_password is None


class TestWebsiteConstruction:
    def test_website_fields(self):
        w = Website(
            url="https://example.com",
            hostname="example.com",
            scheme="https",
        )
        assert w.hostname == "example.com"
        assert w.scheme == "https"

    def test_website_verification_status_default(self):
        w = Website(url="https://x.com", hostname="x.com", scheme="https")
        # default is set by ORM or Python default
        assert w.verification_status in (
            VerificationStatus.UNVERIFIED,
            None,  # before flush
        )

    def test_website_display_name_optional(self):
        w = Website(url="https://x.com", hostname="x.com", scheme="https")
        assert w.display_name is None


class TestDomainVerificationConstruction:
    def test_domain_verification_fields(self):
        wid = uuid.uuid4()
        dv = DomainVerification(
            website_id=wid,
            method=VerificationMethod.DNS_TXT,
            token="abc123",
        )
        assert dv.method == VerificationMethod.DNS_TXT
        assert dv.token == "abc123"
        assert dv.verified_at is None


class TestScanJobConstruction:
    def test_scan_job_fields(self):
        wid = uuid.uuid4()
        job = ScanJob(
            website_id=wid,
            status=ScanStatus.QUEUED,
            profile=ScanProfile.STANDARD,
            requested_url="https://example.com",
        )
        assert job.status == ScanStatus.QUEUED
        assert job.profile == ScanProfile.STANDARD
        assert job.started_at is None
        assert job.error_message is None


class TestScanResultRecordConstruction:
    def test_scan_result_fields(self):
        jid = uuid.uuid4()
        r = ScanResultRecord(
            scan_job_id=jid,
            risk_score=85,
            risk_level="low",
            pages_crawled=5,
            total_findings=3,
            actionable_findings=2,
            severity_breakdown={"critical": 0, "high": 1},
        )
        assert r.risk_score == 85
        assert r.risk_level == "low"
        assert r.severity_breakdown["high"] == 1


class TestFindingRecordConstruction:
    def test_finding_record_fields(self):
        rid = uuid.uuid4()
        f = FindingRecord(
            scan_result_id=rid,
            title="Missing HSTS",
            severity="medium",
            category="security_header",
            scanner_engine="security_headers",
        )
        assert f.title == "Missing HSTS"
        assert f.severity == "medium"
        assert f.evidence is None


class TestGroupedFindingRecordConstruction:
    def test_grouped_finding_fields(self):
        rid = uuid.uuid4()
        gf = GroupedFindingRecord(
            scan_result_id=rid,
            title="Missing HSTS",
            severity="medium",
            category="security_header",
            scanner_engine="security_headers",
            affected_url_count=3,
            affected_urls=["https://example.com/", "https://example.com/about"],
            evidence_count=3,
        )
        assert gf.affected_url_count == 3
        assert len(gf.affected_urls) == 2


class TestEngineDiagnosticRecordConstruction:
    def test_engine_diagnostic_fields(self):
        rid = uuid.uuid4()
        ed = EngineDiagnosticRecord(
            scan_result_id=rid,
            engine_name="csp_engine",
            status="ok",
            findings_count=2,
        )
        assert ed.engine_name == "csp_engine"
        assert ed.skipped_reason is None
        assert ed.error_message is None


class TestBaselineRecordConstruction:
    def test_baseline_record_fields(self):
        wid = uuid.uuid4()
        b = BaselineRecord(
            website_id=wid,
            baseline_id="bl_001",
            baseline_version=1,
            baseline_json={"findings": []},
        )
        assert b.baseline_id == "bl_001"
        assert b.baseline_json["findings"] == []


class TestReportRecordConstruction:
    def test_report_record_fields(self):
        rid = uuid.uuid4()
        r = ReportRecord(
            scan_result_id=rid,
            format=ReportFormat.JSON,
            content_json={"report": "data"},
        )
        assert r.format == ReportFormat.JSON
        assert r.path is None


# ---------------------------------------------------------------------------
# Enum persistence: SAEnum columns must use .value (lowercase) not .name
# ---------------------------------------------------------------------------


def _col_enums(model, colname: str) -> list[str]:
    """Return the list of enum strings that SQLAlchemy will send to the DB."""
    col = sa.inspect(model).c[colname]
    return list(col.type.enums)


class TestEnumPersistenceConfig:
    """Verify every SAEnum column is configured with values_callable so the
    ORM sends lowercase enum values (e.g. 'queued') not names ('QUEUED')
    to PostgreSQL."""

    def test_website_verification_status_lowercase(self):
        vals = _col_enums(Website, "verification_status")
        assert vals == [e.value for e in VerificationStatus]
        assert all(v == v.lower() for v in vals)

    def test_domain_verification_method_lowercase(self):
        vals = _col_enums(DomainVerification, "method")
        assert vals == [e.value for e in VerificationMethod]
        assert all(v == v.lower() for v in vals)

    def test_domain_verification_status_lowercase(self):
        vals = _col_enums(DomainVerification, "status")
        assert vals == [e.value for e in VerificationStatus]
        assert all(v == v.lower() for v in vals)

    def test_scan_job_status_lowercase(self):
        vals = _col_enums(ScanJob, "status")
        assert vals == [e.value for e in ScanStatus]
        assert all(v == v.lower() for v in vals)

    def test_scan_job_profile_lowercase(self):
        vals = _col_enums(ScanJob, "profile")
        assert vals == [e.value for e in ScanProfile]
        assert all(v == v.lower() for v in vals)

    def test_scan_schedule_profile_lowercase(self):
        vals = _col_enums(ScanSchedule, "profile")
        assert vals == [e.value for e in ScanProfile]
        assert all(v == v.lower() for v in vals)

    def test_scan_schedule_frequency_lowercase(self):
        vals = _col_enums(ScanSchedule, "frequency")
        assert vals == [e.value for e in ScheduleFrequency]
        assert all(v == v.lower() for v in vals)

    def test_report_format_lowercase(self):
        vals = _col_enums(ReportRecord, "format")
        assert vals == [e.value for e in ReportFormat]
        assert all(v == v.lower() for v in vals)

    def test_notification_type_lowercase(self):
        vals = _col_enums(Notification, "type")
        assert vals == [e.value for e in NotificationType]
        assert all(v == v.lower() for v in vals)

    def test_notification_severity_lowercase(self):
        vals = _col_enums(Notification, "severity")
        assert vals == [e.value for e in NotificationSeverity]
        assert all(v == v.lower() for v in vals)
