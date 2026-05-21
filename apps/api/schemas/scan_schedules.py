from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from apps.api.pagination import BaseListResponse

from apps.api.models.enums import ScheduleFrequency, ScanProfile


class ScanScheduleCreate(BaseModel):
    website_id: uuid.UUID
    profile: ScanProfile = ScanProfile.STANDARD
    frequency: ScheduleFrequency
    is_enabled: bool = True
    use_latest_baseline: bool = True
    save_baseline: bool = True
    next_run_at: datetime


class ScanSchedulePatch(BaseModel):
    profile: ScanProfile | None = None
    frequency: ScheduleFrequency | None = None
    is_enabled: bool | None = None
    use_latest_baseline: bool | None = None
    save_baseline: bool | None = None
    next_run_at: datetime | None = None


class ScanScheduleResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    website_id: uuid.UUID
    profile: ScanProfile
    frequency: ScheduleFrequency
    is_enabled: bool
    use_latest_baseline: bool
    save_baseline: bool
    next_run_at: datetime
    last_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanScheduleListResponse(BaseListResponse):
    items: list[ScanScheduleResponse]
