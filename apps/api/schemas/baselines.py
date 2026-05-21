from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from apps.api.pagination import BaseListResponse


class BaselineSummary(BaseModel):
    id: uuid.UUID
    website_id: uuid.UUID
    baseline_id: str
    baseline_version: int
    # scan_result_id/scan_job_id are not stored on BaselineRecord; always None
    scan_result_id: str | None = None
    scan_job_id: uuid.UUID | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BaselineDetail(BaseModel):
    id: uuid.UUID
    website_id: uuid.UUID
    baseline_id: str
    baseline_version: int
    baseline_json: dict
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BaselineListResponse(BaseListResponse):
    items: list[BaselineSummary]


class WadeGroupedFinding(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    category: str
    scanner_engine: str
    affected_url_count: int
    confidence: float | None = None
    remediation: str | None = None
    affected_urls: list[str] | None = None

    model_config = ConfigDict(from_attributes=True)


class WadeDiagnostic(BaseModel):
    status: str
    findings_count: int
    severity_counts: dict | None = None
    duration_ms: float | None = None
    skipped_reason: str | None = None
    error_message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class WadeSummary(BaseModel):
    scan_result_id: uuid.UUID
    baseline_generated: bool
    compared_to_previous_baseline: bool
    baseline_version: str | None
    anomaly_count: int
    wade_findings: list[WadeGroupedFinding]
    wade_diagnostic: WadeDiagnostic | None


class WadeHistoryItem(BaseModel):
    scan_result_id: uuid.UUID
    scan_job_id: uuid.UUID
    created_at: datetime
    anomaly_count: int
    risk_score: int
    risk_level: str
    top_anomaly_titles: list[str]


class WadeHistoryResponse(BaseModel):
    items: list[WadeHistoryItem]
    total: int
    limit: int
    offset: int
