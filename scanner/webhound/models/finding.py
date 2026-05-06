# WebHound — scanner/webhound/models/finding.py
# Finding model: a discrete security issue discovered during a scan,
# backed by evidence and aligned to security frameworks (OWASP, CWE, NIST).

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from .evidence import Evidence
from .severity import Severity


class FindingCategory(str, Enum):
    """Logical grouping of finding types, mirrors scanner engine families."""

    SECURITY_HEADER = "security_header"
    COOKIE = "cookie"
    TLS = "tls"
    DNS = "dns"
    JAVASCRIPT = "javascript"
    FORM = "form"
    CORS = "cors"
    COMPROMISE = "compromise"
    RECON = "recon"
    CMS = "cms"
    API = "api"
    TECHNOLOGY = "technology"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class FrameworkAlignment(BaseModel):
    """References to external security classification frameworks."""

    owasp_top10: list[str] = Field(
        default_factory=list,
        description="OWASP Top 10 IDs, e.g. ['A05:2021', 'A06:2021']",
    )
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="CWE identifiers, e.g. ['CWE-79', 'CWE-200']",
    )
    nist_controls: list[str] = Field(
        default_factory=list,
        description="NIST SP 800-53 control IDs, e.g. ['SC-8', 'SI-10']",
    )
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS v3.1 vector string, e.g. 'CVSS:3.1/AV:N/AC:L/...'",
    )
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)


class Finding(BaseModel):
    """A discrete, evidence-backed security issue surfaced during a scan.

    Confidence reflects WADE's certainty that this is a true positive:
      1.0 = confirmed via multiple independent signals
      0.7 = single strong indicator
      0.4 = heuristic / low-signal detection
    """

    id: UUID = Field(default_factory=uuid4)
    title: str = Field(description="Short human-readable finding name.")
    description: str = Field(
        description="Full technical description of the issue and its impact."
    )
    severity: Severity
    category: FindingCategory = Field(default=FindingCategory.UNKNOWN)

    # Supporting evidence — at least one required for non-INFO findings
    evidence: list[Evidence] = Field(default_factory=list)

    # WADE adaptive engine outputs
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="WADE confidence this is a true positive [0.0–1.0].",
    )
    anomaly_score: float | None = Field(
        default=None,
        ge=0.0,
        description="WADE anomaly deviation score vs baseline (higher = more anomalous).",
    )

    # Framework alignment
    framework: FrameworkAlignment = Field(default_factory=FrameworkAlignment)

    # Remediation guidance
    remediation: str | None = Field(default=None)
    references: list[str] = Field(default_factory=list)

    # Classification tags for filtering / reporting
    tags: list[str] = Field(default_factory=list)

    # Provenance
    scanner_engine: str = Field(
        description="Name of the engine that produced this finding."
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Review lifecycle
    false_positive: bool = Field(default=False)
    reviewed: bool = Field(default=False)
    suppressed: bool = Field(default=False)

    # Flexible extension bag
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False, "populate_by_name": True}

    @field_validator("confidence", "anomaly_score", mode="before")
    @classmethod
    def _round_float(cls, v: float | None) -> float | None:
        return round(v, 4) if v is not None else v

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def effective_severity(self) -> Severity:
        """Severity adjusted for confidence — demotes one level when confidence < 0.4."""
        if self.confidence < 0.4 and self.severity.rank > Severity.LOW.rank:
            _demote = {
                Severity.CRITICAL: Severity.HIGH,
                Severity.HIGH: Severity.MEDIUM,
                Severity.MEDIUM: Severity.LOW,
            }
            return _demote.get(self.severity, self.severity)
        return self.severity

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def is_active(self) -> bool:
        return not self.false_positive and not self.suppressed

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, raw: str) -> "Finding":
        return cls.model_validate_json(raw)
