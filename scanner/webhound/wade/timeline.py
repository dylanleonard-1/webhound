# WebHound — scanner/webhound/wade/timeline.py
# WADE 2.0 change timeline (Task 9).
#
# Data structures only — this phase prepares the shape a future dashboard
# will render (change history, first/last seen, frequency, trend). It does
# NOT build UI, schedule monitoring, or persist anything itself; the scanner
# stashes the serialised timeline in scan metadata and a later phase wires
# storage + visualisation.
#
# A "change key" identifies the *same* change recurring across scans
# (e.g. the same new third-party host on the same page), so we can answer
# "how often does this flap?" rather than treating every scan as new.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.wade.change_classifier import ChangeAssessment
from webhound.wade.diff_engine import DiffItem


@dataclass
class ChangeRecord:
    """One distinct change tracked across scans."""

    change_key: str            # stable identity: "diff_type|url|value"
    diff_type: str
    url: str
    value: str | None
    change_type: str           # WadeChangeType value at most recent sighting
    band: str                  # ChangeBand value at most recent sighting
    first_seen: str            # ISO-8601 scan timestamp of first observation
    last_seen: str             # ISO-8601 scan timestamp of latest observation
    occurrences: int = 1       # number of scans this change appeared in

    @property
    def is_recurring(self) -> bool:
        return self.occurrences > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_key": self.change_key,
            "diff_type": self.diff_type,
            "url": self.url,
            "value": self.value,
            "change_type": self.change_type,
            "band": self.band,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "recurring": self.is_recurring,
        }


@dataclass
class ChangeTimeline:
    """A collection of :class:`ChangeRecord` objects keyed by change identity.

    Designed to be merged forward scan-over-scan: feed the prior timeline plus
    this scan's assessed changes and it updates first/last-seen + frequency.
    """

    records: dict[str, ChangeRecord] = field(default_factory=dict)

    # --- trend helpers (cheap, dashboard-ready) -------------------------
    @property
    def total_changes(self) -> int:
        return len(self.records)

    @property
    def recurring_changes(self) -> list[ChangeRecord]:
        return [r for r in self.records.values() if r.is_recurring]

    def band_histogram(self) -> dict[str, int]:
        hist: dict[str, int] = {}
        for r in self.records.values():
            hist[r.band] = hist.get(r.band, 0) + 1
        return hist

    def change_type_histogram(self) -> dict[str, int]:
        hist: dict[str, int] = {}
        for r in self.records.values():
            hist[r.change_type] = hist.get(r.change_type, 0) + 1
        return hist

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_changes": self.total_changes,
            "recurring_count": len(self.recurring_changes),
            "band_histogram": self.band_histogram(),
            "change_type_histogram": self.change_type_histogram(),
            "records": [r.to_dict() for r in self.records.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChangeTimeline":
        tl = cls()
        for rec in data.get("records", []):
            tl.records[rec["change_key"]] = ChangeRecord(
                change_key=rec["change_key"],
                diff_type=rec["diff_type"],
                url=rec["url"],
                value=rec.get("value"),
                change_type=rec.get("change_type", ""),
                band=rec.get("band", ""),
                first_seen=rec["first_seen"],
                last_seen=rec["last_seen"],
                occurrences=int(rec.get("occurrences", 1)),
            )
        return tl


def change_key(item: DiffItem) -> str:
    """Stable identity for a change across scans."""
    return f"{item.diff_type.value}|{item.url}|{item.current_value or ''}"


def update_timeline(
    timeline: ChangeTimeline,
    changes: list[tuple[DiffItem, ChangeAssessment]],
    *,
    scan_timestamp: str,
) -> ChangeTimeline:
    """Fold this scan's (DiffItem, ChangeAssessment) pairs into *timeline*.

    Pure: returns the same (mutated) timeline for chaining. ``scan_timestamp``
    must be supplied by the caller (the engine has a real clock; this module
    deliberately takes no time dependency so it stays trivially testable)."""
    for item, assessment in changes:
        key = change_key(item)
        existing = timeline.records.get(key)
        if existing is None:
            timeline.records[key] = ChangeRecord(
                change_key=key,
                diff_type=item.diff_type.value,
                url=item.url,
                value=item.current_value,
                change_type=assessment.change_type.value,
                band=assessment.band.value,
                first_seen=scan_timestamp,
                last_seen=scan_timestamp,
                occurrences=1,
            )
        else:
            existing.last_seen = scan_timestamp
            existing.occurrences += 1
            existing.change_type = assessment.change_type.value
            existing.band = assessment.band.value
    return timeline
