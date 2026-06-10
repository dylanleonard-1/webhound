from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProviderProfileResponse(BaseModel):
    """Customer-facing provider-stack discovery result for a website."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    website_id: uuid.UUID
    domain: str
    registrar: str | None = None
    dns_provider: str | None = None
    hosting_provider: str | None = None
    cdn_provider: str | None = None
    waf_provider: str | None = None
    cms: str | None = None
    framework: str | None = None
    confidence: int
    evidence: list[str] = []
    detected_at: datetime
