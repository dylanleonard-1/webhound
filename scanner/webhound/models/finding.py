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


class Exploitability(str, Enum):
    """How concretely a finding can be turned into an attack today.

    `theoretical` — defence-in-depth gap; not directly exploitable on its own.
    `practical`   — public exploits exist or the path to one is well-known.
    `known_exploited` — CISA KEV-listed or matched to active in-the-wild abuse.
    """

    THEORETICAL = "theoretical"
    PRACTICAL = "practical"
    KNOWN_EXPLOITED = "known_exploited"
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

    # Compliance framework references. Stored as opaque strings so callers can
    # use whatever ID format the framework version uses (e.g. PCI DSS 4.0
    # numbering is different from 3.2.1).
    pci_dss: list[str] = Field(
        default_factory=list,
        description="PCI DSS requirement IDs, e.g. ['6.4.2', '6.5.6']",
    )
    iso_27001: list[str] = Field(
        default_factory=list,
        description="ISO/IEC 27001:2022 Annex A control IDs, e.g. ['A.8.23', 'A.5.34']",
    )
    soc2: list[str] = Field(
        default_factory=list,
        description="SOC 2 Trust Service Criteria, e.g. ['CC6.6', 'CC6.7']",
    )
    hipaa: list[str] = Field(
        default_factory=list,
        description="HIPAA Security Rule references, e.g. ['164.312(e)(1)']",
    )

    # Triage-relevant exploitability flag.
    exploitability: Exploitability = Field(
        default=Exploitability.UNKNOWN,
        description="How concretely this finding can be turned into an attack today.",
    )


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
    def quality_label(self) -> str:
        """Qualitative label the dashboard renders next to each finding,
        derived from severity + confidence + tags. Used to demote weak
        heuristics out of Fix-First and to make "this is just FYI" explicit
        in exports / compliance reports.

        Possible values: `confirmed`, `likely`, `heuristic`, `advisory`,
        `informational`.
        """
        tags = {t.lower() for t in (self.tags or [])}
        if self.severity == Severity.INFO:
            return "advisory" if "advisory" in tags else "informational"
        if "heuristic" in tags or "weak_signal" in tags or self.confidence < 0.55:
            return "heuristic"
        if "confirmed" in tags or self.confidence >= 0.9:
            return "confirmed"
        if "likely" in tags or self.confidence >= 0.7:
            return "likely"
        return "heuristic"

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
