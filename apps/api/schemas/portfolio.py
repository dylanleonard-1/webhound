# WebHound API — apps/api/schemas/portfolio.py
# Phase-16 portfolio API schemas.

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PortfolioSiteRow(BaseModel):
    site_id: str
    domain: str
    url: str
    group_id: str | None = None
    risk_score: int = 0
    risk_level: str = "safe"
    monitoring: bool = False
    last_scan_at: str | None = None
    wade_changed: bool = False


class PortfolioSummaryResponse(BaseModel):
    summary: dict[str, Any]
    dashboard: dict[str, Any]
    report: dict[str, Any]


class PortfolioAlertsResponse(BaseModel):
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class PortfolioRiskRollupResponse(BaseModel):
    rollup: dict[str, Any]
    scores: dict[str, Any]


class ClientGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    group_type: str = "agency_client"
    parent_group_id: str | None = None


class ClientGroupResponse(BaseModel):
    group_id: str
    name: str
    group_type: str
    parent_group_id: str | None = None
    site_count: int = 0


class ClientGroupListResponse(BaseModel):
    groups: list[ClientGroupResponse] = Field(default_factory=list)


class AssignGroupRequest(BaseModel):
    group_id: str | None = None       # None clears the assignment


class PortfolioReportResponse(BaseModel):
    report: dict[str, Any]
