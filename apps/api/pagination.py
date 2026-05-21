from __future__ import annotations

from pydantic import BaseModel


class BaseListResponse(BaseModel):
    """Base for all paginated list responses. Subclasses add a typed `items` field."""

    total: int
    limit: int
    offset: int
    has_more: bool = False
    next_offset: int | None = None


def page_meta(total: int, limit: int, offset: int) -> dict:
    """Return has_more and next_offset for inclusion in a list response."""
    has_more = total > offset + limit
    return {"has_more": has_more, "next_offset": offset + limit if has_more else None}
