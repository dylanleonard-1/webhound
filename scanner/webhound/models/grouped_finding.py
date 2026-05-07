# WebHound — scanner/webhound/models/grouped_finding.py
# GroupedFinding: an aggregated view of repeated raw Finding objects that
# represent the same distinct security issue detected across multiple pages.

from __future__ import annotations

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

    model_config = {"frozen": False, "populate_by_name": True}
