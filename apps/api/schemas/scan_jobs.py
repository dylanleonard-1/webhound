from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from apps.api.models.enums import ScanProfile, ScanStatus


class ScanJobCreate(BaseModel):
    website_id: uuid.UUID
    profile: ScanProfile = ScanProfile.STANDARD
    use_latest_baseline: bool = False
    save_baseline: bool = True


class ScanJobStatusUpdate(BaseModel):
    status: ScanStatus
    error_message: str | None = None


class ScanJobResponse(BaseModel):
    id: uuid.UUID
    website_id: uuid.UUID
    status: ScanStatus
    profile: ScanProfile
    requested_url: str
    use_latest_baseline: bool
    save_baseline: bool
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    celery_task_id: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanJobListResponse(BaseModel):
    items: list[ScanJobResponse]
    total: int
    limit: int
    offset: int
