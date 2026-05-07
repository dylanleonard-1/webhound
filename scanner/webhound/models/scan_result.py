# WebHound — scanner/webhound/models/scan_result.py
# ScanResult model: aggregated output of a complete scan run —
# findings, severity counts, risk score, timing, and engine provenance.

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, computed_field, model_validator

from .engine_status import EngineStatus
from .finding import Finding
from .severity import Severity
from .target import Target


class ScanStatus(str, Enum):
    """Lifecycle status of a scan run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"  # Completed with some engine errors


class SeverityBreakdown(BaseModel):
    """Count of active (non-suppressed, non-FP) findings per severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @property
    def actionable(self) -> int:
        """Findings that warrant immediate attention (CRITICAL + HIGH + MEDIUM)."""
        return self.critical + self.high + self.medium


class ScanError(BaseModel):
    """A non-fatal error recorded during a scan (engine failure, timeout, etc.)."""

    engine: str
    message: str
    url: str | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recoverable: bool = True


class ScanResult(BaseModel):
    """Complete output of a single scan run against a Target."""

    id: UUID = Field(default_factory=uuid4)
    target: Target
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    findings: list[Finding] = Field(default_factory=list)

    # Risk aggregation
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    overall_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Aggregate risk score [0–10] computed from findings + confidence.",
    )
    scan_confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Average confidence across all active findings.",
    )

    # Timing
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = Field(default=None)

    # Engine / crawler telemetry
    scanner_version: str = Field(default="0.1.0")
    engines_run: list[str] = Field(default_factory=list)
    urls_crawled: int = Field(default=0, ge=0)
    pages_analyzed: int = Field(default=0, ge=0)
    requests_made: int = Field(default=0, ge=0)

    # Non-fatal errors encountered during the run
    errors: list[ScanError] = Field(default_factory=list)

    # Per-engine execution diagnostics (populated at scan completion)
    engine_diagnostics: list[EngineStatus] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False, "populate_by_name": True}

    # ------------------------------------------------------------------
    # Derived / computed helpers
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_active]

    def recompute_aggregates(self) -> None:
        """Rebuild severity_breakdown and overall_risk_score from current findings."""
        active = self.active_findings
        bd = SeverityBreakdown()
        for f in active:
            match f.severity:
                case Severity.CRITICAL:
                    bd.critical += 1
                case Severity.HIGH:
                    bd.high += 1
                case Severity.MEDIUM:
                    bd.medium += 1
                case Severity.LOW:
                    bd.low += 1
                case Severity.INFO:
                    bd.info += 1
        self.severity_breakdown = bd

        if active:
            weighted = sum(f.severity.numeric_score * f.confidence for f in active)
            self.overall_risk_score = round(
                min(10.0, weighted / len(active)), 2
            )
            self.scan_confidence = round(
                sum(f.confidence for f in active) / len(active), 4
            )
        else:
            self.overall_risk_score = 0.0
            self.scan_confidence = 1.0

    def mark_complete(self) -> None:
        self.completed_at = datetime.now(timezone.utc)
        self.status = ScanStatus.COMPLETED
        self.recompute_aggregates()

    def mark_failed(self, reason: str = "") -> None:
        self.completed_at = datetime.now(timezone.utc)
        self.status = ScanStatus.FAILED
        if reason:
            self.metadata["failure_reason"] = reason

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: ScanError) -> None:
        self.errors.append(error)

    # ------------------------------------------------------------------
    # Summary / reporting helpers
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "target": self.target.base_url,
            "status": self.status.value,
            "overall_risk_score": self.overall_risk_score,
            "scan_confidence": self.scan_confidence,
            "findings": {
                "total": len(self.findings),
                "active": len(self.active_findings),
                "critical": self.severity_breakdown.critical,
                "high": self.severity_breakdown.high,
                "medium": self.severity_breakdown.medium,
                "low": self.severity_breakdown.low,
                "info": self.severity_breakdown.info,
            },
            "duration_seconds": self.duration_seconds,
            "urls_crawled": self.urls_crawled,
            "pages_analyzed": self.pages_analyzed,
            "engines_run": self.engines_run,
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, raw: str) -> "ScanResult":
        return cls.model_validate_json(raw)
