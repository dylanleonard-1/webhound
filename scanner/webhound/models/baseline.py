# WebHound — scanner/webhound/models/baseline.py
# Baseline model: a statistical snapshot of normal website behaviour used by the
# WADE adaptive detection engine to score anomalies at scan time.
#
# A baseline must be built before WADE can produce anomaly_score values on findings.

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class BaselineStatus(str, Enum):
    """Lifecycle status of a baseline record."""

    BUILDING = "building"   # Sampling in progress
    READY = "ready"         # Sufficient samples collected, ready for comparison
    STALE = "stale"         # Too old to be relied upon
    INVALID = "invalid"     # Corrupted or failed to build


class ResponseProfile(BaseModel):
    """Statistical profile of HTTP responses for a single URL pattern."""

    url_pattern: str = Field(description="URL or glob pattern this profile covers.")
    status_codes: dict[str, int] = Field(
        default_factory=dict,
        description="Frequency map of observed status codes, e.g. {'200': 50, '301': 5}.",
    )
    content_length_mean: float | None = Field(default=None)
    content_length_stddev: float | None = Field(default=None)
    response_time_p50_ms: float | None = Field(default=None)
    response_time_p90_ms: float | None = Field(default=None)
    response_time_p99_ms: float | None = Field(default=None)
    common_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Headers that appear consistently across sampled responses.",
    )
    content_hash_samples: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashes of normalised page content from sample responses.",
    )
    sample_count: int = Field(default=0, ge=0)


class BaselineEntry(BaseModel):
    """A single raw observation captured during baseline building."""

    url: str
    status_code: int = Field(ge=100, le=599)
    content_length: int = Field(ge=0)
    response_time_ms: float = Field(ge=0.0)
    headers: dict[str, str] = Field(default_factory=dict)
    content_hash: str = Field(description="SHA-256 of normalised response body.")
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    extra: dict[str, Any] = Field(default_factory=dict)


class Baseline(BaseModel):
    """Behavioural snapshot of a target website used by WADE for anomaly detection.

    Anomaly scoring compares real-time observations against this baseline.
    Scores > anomaly_threshold trigger elevated finding confidence.
    """

    id: UUID = Field(default_factory=uuid4)
    target_id: UUID = Field(description="ID of the Target this baseline belongs to.")
    status: BaselineStatus = Field(default=BaselineStatus.BUILDING)

    # Sample data
    entries: list[BaselineEntry] = Field(default_factory=list)
    profiles: list[ResponseProfile] = Field(
        default_factory=list,
        description="Aggregated statistical profiles per URL pattern.",
    )

    # Security-relevant header fingerprints observed as normal
    header_fingerprint: dict[str, str] = Field(
        default_factory=dict,
        description="Headers and their expected values (e.g. CSP, X-Frame-Options).",
    )

    # WADE sensitivity knob
    anomaly_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Normalised deviation score above which WADE flags an anomaly.",
    )

    # Lifecycle
    built_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=30)
    )
    last_updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    scanner_version: str = Field(default="0.1.0")
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False, "populate_by_name": True}

    @field_validator("anomaly_threshold")
    @classmethod
    def _round_threshold(cls, v: float) -> float:
        return round(v, 4)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def sample_count(self) -> int:
        return len(self.entries)

    @property
    def is_ready(self) -> bool:
        return self.status == BaselineStatus.READY

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_usable(self) -> bool:
        return self.is_ready and not self.is_expired

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_entry(self, entry: BaselineEntry) -> None:
        self.entries.append(entry)
        self.last_updated_at = datetime.now(timezone.utc)

    def mark_ready(self) -> None:
        self.status = BaselineStatus.READY
        self.built_at = datetime.now(timezone.utc)
        self.last_updated_at = self.built_at

    def mark_stale(self) -> None:
        self.status = BaselineStatus.STALE

    def extend_expiry(self, days: int = 30) -> None:
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Baseline":
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, raw: str) -> "Baseline":
        return cls.model_validate_json(raw)
