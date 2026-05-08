from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from apps.api.models.enums import ReportFormat


class WebsiteSummary(BaseModel):
    id: uuid.UUID
    url: str
    hostname: str
    scheme: str

    model_config = ConfigDict(from_attributes=True)


class ScanJobSummary(BaseModel):
    id: uuid.UUID
    website_id: uuid.UUID
    profile: str
    requested_url: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResultSummary(BaseModel):
    id: uuid.UUID
    scan_job_id: uuid.UUID
    website_id: uuid.UUID
    requested_url: str
    hostname: str
    risk_score: int
    risk_level: str
    duration_seconds: float | None = None
    pages_crawled: int
    total_findings: int
    actionable_findings: int
    severity_breakdown: dict
    created_at: datetime


class ScanResultListResponse(BaseModel):
    items: list[ScanResultSummary]
    total: int
    limit: int
    offset: int


class ScanResultDetail(BaseModel):
    id: uuid.UUID
    scan_job_id: uuid.UUID
    scan_id: str | None = None
    risk_score: int
    risk_level: str
    duration_seconds: float | None = None
    pages_crawled: int
    total_findings: int
    actionable_findings: int
    severity_breakdown: dict
    scanner_metadata: dict | None = None
    created_at: datetime

    scan_job: ScanJobSummary
    website: WebsiteSummary


class GroupedFindingResponse(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    category: str
    scanner_engine: str
    affected_url_count: int
    affected_urls: list[str] | None = None
    evidence_count: int
    confidence: float | None = None
    remediation: str | None = None
    framework: dict | None = None
    finding_ids: list[str] | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GroupedFindingListResponse(BaseModel):
    items: list[GroupedFindingResponse]
    total: int
    limit: int
    offset: int


class FindingResponse(BaseModel):
    id: uuid.UUID
    scanner_finding_id: str | None = None
    title: str
    severity: str
    category: str
    scanner_engine: str
    affected_url: str | None = None
    confidence: float | None = None
    description: str | None = None
    remediation: str | None = None
    evidence: list | None = None
    framework: dict | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class EngineDiagnosticResponse(BaseModel):
    id: uuid.UUID
    engine_name: str
    category: str | None = None
    status: str
    findings_count: int
    severity_counts: dict | None = None
    duration_ms: float | None = None
    skipped_reason: str | None = None
    error_message: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportResponse(BaseModel):
    id: uuid.UUID
    format: ReportFormat
    path: str | None = None
    content_json: dict | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
