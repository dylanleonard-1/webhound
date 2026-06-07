# WebHound — scanner/webhound/monitoring/change_history.py
# Phase-11 monitoring: the persistent change-history model + the shared
# vocabulary (alert tiers, change categories) the whole monitoring layer
# speaks. Pure data + serialization — no network, no I/O.
#
# This is the structure a future dashboard renders (Task 10) and the
# structure change_tracker accumulates scan-over-scan (Task 1/2).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AlertTier(str, Enum):
    """Customer-facing alert levels (Task 3), benign → urgent."""

    INFORMATIONAL = "informational"
    NOTICE = "notice"
    REVIEW = "review"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _TIER_RANK[self.value]


_TIER_RANK = {
    "informational": 0, "notice": 1, "review": 2,
    "warning": 3, "critical": 4,
}


class ChangeCategory(str, Enum):
    """What kind of change this is (Task 6)."""

    SECURITY = "security_change"
    CONTENT = "content_change"
    VENDOR = "vendor_change"
    INFRASTRUCTURE = "infrastructure_change"
    AUTHENTICATION = "authentication_change"
    PAYMENT = "payment_change"
    TECHNOLOGY = "technology_change"
    POSSIBLE_COMPROMISE = "possible_compromise"


class RiskDirection(str, Enum):
    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"


# What kind of asset changed (Task 1 — the things we track).
class TrackedAsset(str, Enum):
    SCRIPT = "script"
    FORM = "form"
    PAGE = "page"
    HEADER = "header"
    COOKIE = "cookie"
    THIRD_PARTY = "third_party_domain"
    API = "api_endpoint"
    IFRAME = "iframe"
    REDIRECT = "redirect"
    TECHNOLOGY = "technology"
    AUTH_SURFACE = "auth_surface"
    OTHER = "other"


@dataclass
class ChangeEvent:
    """One distinct change tracked across scans (Task 1, 2, 10).

    ``change_key`` is the stable cross-scan identity (mirrors the WADE
    timeline key) so the same change accumulates first/last-seen +
    frequency rather than re-appearing each scan."""

    change_key: str
    asset: str                       # TrackedAsset value
    category: str                    # ChangeCategory value
    tier: str                        # AlertTier value
    direction: str                   # RiskDirection value
    title: str
    detail: str = ""
    url: str | None = None
    confidence: str = "medium"       # confirmed/high/medium/low/heuristic
    first_seen: str = ""             # ISO-8601
    last_seen: str = ""              # ISO-8601
    occurrences: int = 1
    status: str = "open"             # open / acknowledged / resolved
    suppressed: bool = False
    suppression_reason: str | None = None

    @property
    def is_recurring(self) -> bool:
        return self.occurrences > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_key": self.change_key,
            "asset": self.asset,
            "category": self.category,
            "tier": self.tier,
            "direction": self.direction,
            "title": self.title,
            "detail": self.detail,
            "url": self.url,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "recurring": self.is_recurring,
            "status": self.status,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ChangeEvent":
        return cls(
            change_key=d["change_key"],
            asset=d.get("asset", TrackedAsset.OTHER.value),
            category=d.get("category", ChangeCategory.CONTENT.value),
            tier=d.get("tier", AlertTier.INFORMATIONAL.value),
            direction=d.get("direction", RiskDirection.UNCHANGED.value),
            title=d.get("title", ""),
            detail=d.get("detail", ""),
            url=d.get("url"),
            confidence=d.get("confidence", "medium"),
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            occurrences=int(d.get("occurrences", 1)),
            status=d.get("status", "open"),
            suppressed=bool(d.get("suppressed", False)),
            suppression_reason=d.get("suppression_reason"),
        )


@dataclass
class ChangeHistory:
    """All tracked changes for one site, keyed by change identity.

    Designed to be loaded from storage, merged forward with a new scan's
    changes, and re-persisted (the cross-scan accumulation the WADE
    timeline couldn't do on its own)."""

    target: str = ""
    records: dict[str, ChangeEvent] = field(default_factory=dict)
    scan_count: int = 0
    last_scan_at: str | None = None

    @property
    def total_changes(self) -> int:
        return len(self.records)

    @property
    def recurring(self) -> list[ChangeEvent]:
        return [e for e in self.records.values() if e.is_recurring]

    def open_events(self) -> list[ChangeEvent]:
        return [e for e in self.records.values()
                if e.status == "open" and not e.suppressed]

    def tier_histogram(self) -> dict[str, int]:
        hist: dict[str, int] = {}
        for e in self.records.values():
            hist[e.tier] = hist.get(e.tier, 0) + 1
        return hist

    def category_histogram(self) -> dict[str, int]:
        hist: dict[str, int] = {}
        for e in self.records.values():
            hist[e.category] = hist.get(e.category, 0) + 1
        return hist

    def timeline(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """Dashboard timeline entries (Task 10), newest first."""
        events = sorted(
            self.records.values(),
            key=lambda e: (e.last_seen, AlertTier(e.tier).rank
                           if e.tier in _TIER_RANK else 0),
            reverse=True,
        )
        return [
            {
                "date": e.last_seen,
                "first_seen": e.first_seen,
                "change": e.title,
                "asset": e.asset,
                "category": e.category,
                "risk_impact": e.direction,
                "confidence": e.confidence,
                "tier": e.tier,
                "status": e.status,
                "recurring": e.is_recurring,
                "occurrences": e.occurrences,
            }
            for e in events[:limit]
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_count": self.scan_count,
            "last_scan_at": self.last_scan_at,
            "total_changes": self.total_changes,
            "recurring_count": len(self.recurring),
            "tier_histogram": self.tier_histogram(),
            "category_histogram": self.category_histogram(),
            "records": [e.to_dict() for e in self.records.values()],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "ChangeHistory":
        hist = cls(
            target=(d or {}).get("target", ""),
            scan_count=int((d or {}).get("scan_count", 0)),
            last_scan_at=(d or {}).get("last_scan_at"),
        )
        for rec in (d or {}).get("records", []) or []:
            try:
                ev = ChangeEvent.from_dict(rec)
                hist.records[ev.change_key] = ev
            except Exception:  # noqa: BLE001
                continue
        return hist
