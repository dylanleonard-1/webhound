# WebHound — scanner/webhound/telemetry/exporters.py
# Phase-2 telemetry exporters. Turn a recorder's event stream into:
#   * to_event_list   — the full ordered timeline (for the internal API /
#                       DB sink).
#   * to_audit_trace  — the black-box recorder (audit_trace.json).
#   * to_metadata_summary — a compact summary folded into
#                       scan_result.metadata.telemetry (the default sink;
#                       no raw timeline shipped by default).

from __future__ import annotations

from collections import Counter
from typing import Any

from webhound.telemetry.events import EventType, Stage
from webhound.telemetry.recorder import TelemetryRecorder


def to_event_list(recorder: TelemetryRecorder) -> list[dict[str, Any]]:
    return [e.to_dict() for e in recorder.events()]


def _engine_rollup(recorder: TelemetryRecorder) -> dict[str, dict[str, Any]]:
    """Per-engine view derived from engine.* events (mirrors the
    EngineTracker summary, but as a telemetry artifact)."""
    rollup: dict[str, dict[str, Any]] = {}
    for e in recorder.events():
        if e.stage is not Stage.ENGINE or not e.engine:
            continue
        slot = rollup.setdefault(e.engine, {})
        if e.event_type is EventType.ENGINE_FINISHED:
            slot["duration_ms"] = e.duration_ms
            slot["findings"] = e.outputs.get("findings")
            slot["suppressed"] = e.outputs.get("suppressed")
            slot["status"] = e.status.value
            if e.metadata.get("decision"):
                slot["decision"] = e.metadata["decision"]
        elif e.event_type is EventType.ENGINE_FAILED:
            slot["status"] = "error"
            slot["errors"] = e.errors
        elif e.event_type is EventType.ENGINE_SKIPPED:
            slot["status"] = "skipped"
            slot["skipped_reason"] = e.metadata.get("reason")
    return rollup


def to_metadata_summary(recorder: TelemetryRecorder) -> dict[str, Any]:
    """Compact, customer-SAFE-but-internal summary for metadata.telemetry.
    Counts + handoffs + engine rollup — no full timeline."""
    type_counts = Counter(e.event_type.value for e in recorder.events())
    stage_counts = Counter(e.stage.value for e in recorder.events())
    errors = [e.to_dict() for e in recorder.events()
              if e.status.value == "error"]
    return {
        "level": recorder.level,
        "event_count": recorder.event_count,
        "dropped_events": recorder.dropped_events,
        "event_type_counts": dict(type_counts),
        "stage_counts": dict(stage_counts),
        "handoffs": dict(recorder.handoffs),
        "engines": _engine_rollup(recorder),
        "error_count": len(errors),
        "errors": [{"engine": e["engine"], "type": e["event_type"],
                    "errors": e["errors"]} for e in errors][:20],
    }


def to_audit_trace(recorder: TelemetryRecorder) -> dict[str, Any]:
    """The black-box recorder: full timeline + derived rollups, replayable
    by iterating `timeline` in sequence order."""
    events = recorder.events()
    type_counts = Counter(e.event_type.value for e in events)

    def _count(et: EventType) -> int:
        return type_counts.get(et.value, 0)

    return {
        "scan_id": recorder.scan_id,
        "job_id": recorder.job_id,
        "telemetry_level": recorder.level,
        "event_count": recorder.event_count,
        "dropped_events": recorder.dropped_events,
        "timeline": to_event_list(recorder),
        "handoffs": dict(recorder.handoffs),
        "engines": _engine_rollup(recorder),
        "findings": {
            "created": _count(EventType.FINDING_CREATED),
            "suppressed": _count(EventType.FINDING_SUPPRESSED),
            "escalated": _count(EventType.FINDING_ESCALATED),
            "correlated": _count(EventType.FINDING_CORRELATED),
        },
        "wade": {
            "baseline_loaded": _count(EventType.WADE_BASELINE_LOADED) > 0,
            "changes_detected": _count(EventType.WADE_CHANGE_DETECTED),
        },
        "correlation": {
            "chains_created": _count(EventType.CORRELATION_CHAIN_CREATED),
            "escalations": _count(EventType.CORRELATION_SEVERITY_ESCALATED),
        },
        "persistence": {
            "saved": _count(EventType.SAVE_FINISHED) > 0,
            "failed": _count(EventType.SAVE_FAILED) > 0,
        },
    }
