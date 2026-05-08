from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from apps.api._url_utils import URLValidationError, normalize_url
from apps.api.models.enums import VerificationStatus


class WebsiteCreate(BaseModel):
    url: str
    display_name: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            normalized, _scheme, _host = normalize_url(v)
        except URLValidationError as exc:
            raise ValueError(str(exc)) from exc
        return normalized


class WebsitePatch(BaseModel):
    display_name: str | None = None
    verification_status: VerificationStatus | None = None

    model_config = ConfigDict(extra="ignore")


class WebsiteResponse(BaseModel):
    id: uuid.UUID
    url: str
    hostname: str
    scheme: str
    display_name: str | None = None
    verification_status: VerificationStatus
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WebsiteListResponse(BaseModel):
    items: list[WebsiteResponse]
    total: int
    limit: int
    offset: int
