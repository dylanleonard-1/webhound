# WebHound — scanner/webhound/telemetry/search.py
# Phase-2 telemetry search. Pure, in-memory query helpers over a list of
# event dicts (the shape produced by exporters.to_event_list). The
# internal admin API loads a scan's events then filters with these; the
# same predicates map 1:1 to SQL WHERE clauses when DB persistence is
# opted in later.

from __future__ import annotations

from typing import Any, Iterable


def search_events(
    events: Iterable[dict[str, Any]],
    *,
    engine: str | None = None,
    event_type: str | None = None,
    stage: str | None = None,
    status: str | None = None,
    error_contains: str | None = None,
    min_duration_ms: float | None = None,
    max_duration_ms: float | None = None,
    since: str | None = None,        # ISO timestamp (inclusive)
    until: str | None = None,        # ISO timestamp (inclusive)
) -> list[dict[str, Any]]:
    """Filter events by any combination of axes; results stay in `sequence`
    order (the canonical timeline order)."""
    out: list[dict[str, Any]] = []
    for e in events:
        if engine is not None and e.get("engine") != engine:
            continue
        if event_type is not None and e.get("event_type") != event_type:
            continue
        if stage is not None and e.get("stage") != stage:
            continue
        if status is not None and e.get("status") != status:
            continue
        if error_contains is not None:
            blob = " ".join(e.get("errors") or [])
            if error_contains.lower() not in blob.lower():
                continue
        dur = e.get("duration_ms")
        if min_duration_ms is not None and (dur is None or dur < min_duration_ms):
            continue
        if max_duration_ms is not None and (dur is None or dur > max_duration_ms):
            continue
        ts = e.get("timestamp") or ""
        if since is not None and ts < since:
            continue
        if until is not None and ts > until:
            continue
        out.append(e)
    out.sort(key=lambda e: e.get("sequence", 0))
    return out


def errors_only(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return search_events(events, status="error")


def slowest(events: Iterable[dict[str, Any]], n: int = 5) -> list[dict[str, Any]]:
    timed = [e for e in events if e.get("duration_ms") is not None]
    timed.sort(key=lambda e: e["duration_ms"], reverse=True)
    return timed[:n]
