# WebHound — scanner/webhound/models/grouped_finding.py
# GroupedFinding: an aggregated view of repeated raw Finding objects that
# represent the same distinct security issue detected across multiple pages.

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .finding import FindingCategory, FrameworkAlignment
from .severity import Severity


class GroupedFinding(BaseModel):
    """One distinct security issue, potentially observed on many pages.

    Aggregates repeated raw findings for cleaner reporting and fair risk
    scoring — the same missing header found on 50 pages counts as one issue,
    not 50.  Raw findings are preserved in ``ScanResult.findings``; this
    object carries their combined context.
    """

    title: str
    severity: Severity
    category: FindingCategory
    scanner_engine: str
    description: str
    remediation: str | None = None

    # Aggregated URL data
    affected_url_count: int = 1
    affected_urls: list[str] = Field(default_factory=list)  # sample, max 10

    # Evidence aggregation
    evidence_count: int = 1  # total raw findings collapsed into this group

    # Quality / scoring
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    framework: FrameworkAlignment = Field(default_factory=FrameworkAlignment)
    anomaly_score: float | None = None

    # Back-references to raw findings (UUID strings)
    finding_ids: list[str] = Field(default_factory=list)

    # Phase-3/4 v4 surface — tags (e.g. 'corroborated', 'cluster',
    # 'heuristic'), free-form metadata bag (mirrors Finding.metadata),
    # and the derived quality_label that the dashboard / SIEM
    # consumers rely on. Default empty so existing fixtures keep
    # working unchanged.
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Phase-8 correlation: primary security story this grouped finding
    # belongs to (None when uncorrelated). Mirrors Finding.
    correlation_id: str | None = Field(default=None)
    correlation_type: str | None = Field(default=None)
    correlation_confidence: str | None = Field(default=None)

    model_config = {"frozen": False, "populate_by_name": True}

    @property
    def quality_label(self) -> str:
        """Mirror of :pyattr:`Finding.quality_label`."""
        tags = {t.lower() for t in (self.tags or [])}
        if self.severity == Severity.INFO:
            return "advisory" if "advisory" in tags else "informational"
        if ("heuristic" in tags or "weak_signal" in tags
                or self.confidence < 0.55):
            return "heuristic"
        if "confirmed" in tags or self.confidence >= 0.9:
            return "confirmed"
        if "likely" in tags or self.confidence >= 0.7:
            return "likely"
        return "heuristic"
