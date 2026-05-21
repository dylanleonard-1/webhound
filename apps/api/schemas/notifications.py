from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from apps.api.pagination import BaseListResponse

from apps.api.models.enums import NotificationSeverity, NotificationType


class NotificationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    website_id: uuid.UUID | None = None
    scan_job_id: uuid.UUID | None = None
    scan_result_id: uuid.UUID | None = None
    type: NotificationType
    severity: NotificationSeverity
    title: str
    message: str
    is_read: bool
    extra_metadata: dict | None = None
    created_at: datetime
    read_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class NotificationListResponse(BaseListResponse):
    items: list[NotificationResponse]


class UnreadCountResponse(BaseModel):
    count: int
