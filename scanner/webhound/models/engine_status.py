# WebHound — scanner/webhound/models/engine_status.py
# Per-engine execution record captured during a scan run.

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class EngineRunStatus(str, Enum):
    """Outcome of a single engine's execution during a scan."""

    PASSED = "passed"       # ran successfully, 0 findings
    FINDINGS = "findings"   # ran successfully, ≥1 findings
    SKIPPED = "skipped"     # intentionally not called (no API key, no targets, etc.)
    FAILED = "failed"       # raised an exception during execution


class EngineStatus(BaseModel):
    """Execution record for one scanner engine within a completed scan.

    Engines that run on multiple pages produce a single aggregated record:
    ``findings_count`` and ``duration_ms`` are totals across all pages.
    """

    name: str = Field(description="Engine identifier, e.g. 'security_headers'.")
    category: str = Field(description="Engine family, e.g. 'headers', 'tls_dns'.")
    status: EngineRunStatus
    findings_count: int = 0
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        },
        description="Per-severity breakdown of findings produced by this engine.",
    )
    skipped_reason: str | None = None
    error_message: str | None = None
    duration_ms: float = Field(
        default=0.0,
        description="Total wall-clock time for this engine across all pages (ms).",
    )
    affected_target: str | None = Field(
        default=None,
        description="Target URL or page URL when a single target is relevant.",
    )
    is_passive: bool = Field(
        default=True,
        description="True when the engine only reads — no mutations, no exploitation.",
    )
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"frozen": False, "populate_by_name": True}

    @property
    def is_healthy(self) -> bool:
        return self.status != EngineRunStatus.FAILED

    @property
    def ran(self) -> bool:
        return self.status in (EngineRunStatus.PASSED, EngineRunStatus.FINDINGS)
