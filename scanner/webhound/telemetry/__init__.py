# WebHound — scanner/webhound/telemetry/__init__.py
# Phase-2 telemetry foundation. Observability only — emitting telemetry
# never changes scan behaviour.

from webhound.telemetry.events import (
    EventType,
    Stage,
    Status,
    TelemetryEvent,
)
from webhound.telemetry.exporters import (
    to_audit_trace,
    to_event_list,
    to_metadata_summary,
)
from webhound.telemetry.recorder import (
    NullRecorder,
    TelemetryRecorder,
    build_recorder,
    resolve_level,
)
from webhound.telemetry.redaction import redact, safe_payload
from webhound.telemetry.search import errors_only, search_events, slowest

__all__ = [
    "EventType", "Stage", "Status", "TelemetryEvent",
    "TelemetryRecorder", "NullRecorder", "build_recorder", "resolve_level",
    "redact", "safe_payload",
    "to_audit_trace", "to_event_list", "to_metadata_summary",
    "search_events", "errors_only", "slowest",
]
