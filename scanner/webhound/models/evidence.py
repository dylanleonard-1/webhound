# WebHound — scanner/webhound/models/evidence.py
# Evidence model: a single artifact captured during scanning that supports a finding.
# Each piece of evidence records what was observed, where, and how confident we are.

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_serializer


class EvidenceType(str, Enum):
    """Classification of evidence artifact type."""

    HTTP_RESPONSE = "http_response"
    HTTP_REQUEST = "http_request"
    HTML_ELEMENT = "html_element"
    HEADER = "header"
    JAVASCRIPT = "javascript"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    COOKIE = "cookie"
    REDIRECT = "redirect"
    PATTERN_MATCH = "pattern_match"
    SCREENSHOT = "screenshot"
    RAW = "raw"


class Evidence(BaseModel):
    """A single observable artifact that supports a security finding.

    Confidence is expressed as a float in [0.0, 1.0]:
      1.0 = definitively observed
      0.7 = strong indicator
      0.4 = weak signal / heuristic
      0.0 = no confidence
    """

    id: UUID = Field(default_factory=uuid4)
    evidence_type: EvidenceType
    content: str = Field(
        description="Raw captured content — header value, HTML snippet, pattern match, etc."
    )
    location: str = Field(description="URL or path where this evidence was captured.")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence this evidence is accurate [0.0–1.0].",
    )
    source_engine: str = Field(
        description="Name of the scanner engine that produced this evidence."
    )
    captured_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # HTTP-specific optional context
    request_method: str | None = Field(default=None)
    status_code: int | None = Field(default=None, ge=100, le=599)
    response_headers: dict[str, str] | None = Field(default=None)

    # Flexible extension bag — never validated, carries engine-specific data
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False, "populate_by_name": True}

    @field_validator("confidence")
    @classmethod
    def _round_confidence(cls, v: float) -> float:
        return round(v, 4)

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, raw: str) -> "Evidence":
        return cls.model_validate_json(raw)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def http_header(
        cls,
        header_name: str,
        header_value: str,
        location: str,
        source_engine: str,
        confidence: float = 1.0,
    ) -> "Evidence":
        return cls(
            evidence_type=EvidenceType.HEADER,
            content=f"{header_name}: {header_value}",
            location=location,
            confidence=confidence,
            source_engine=source_engine,
            extra={"header_name": header_name, "header_value": header_value},
        )

    @classmethod
    def pattern_match(
        cls,
        pattern: str,
        matched_text: str,
        location: str,
        source_engine: str,
        confidence: float = 0.8,
    ) -> "Evidence":
        return cls(
            evidence_type=EvidenceType.PATTERN_MATCH,
            content=matched_text,
            location=location,
            confidence=confidence,
            source_engine=source_engine,
            extra={"pattern": pattern},
        )
