# WebHound — scanner/webhound/telemetry/events.py
# Phase-2 telemetry foundation: the event model + taxonomy. An event is an
# immutable, JSON-safe record of one observable moment in a scan. Events
# carry COUNTS/IDS/DURATIONS only — never finding bodies, never secrets
# (redaction is applied by the recorder before storage).
#
# Observability only. Emitting events never changes scan behaviour.

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Stage(str, Enum):
    SCAN = "scan"
    PROFILE = "profile"
    CRAWL = "crawl"
    BROWSER = "browser"
    FRAMEWORK = "framework"
    ENGINE = "engine"
    FINDING = "finding"
    WADE = "wade"
    CORRELATION = "correlation"
    REPORT = "report"
    PERSISTENCE = "persistence"
    HANDOFF = "handoff"


class Status(str, Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"
    INFO = "info"


class EventType(str, Enum):
    # scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_FINISHED = "scan.finished"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    # profile
    PROFILE_LOADED = "profile.loaded"
    PROFILE_VALIDATION = "profile.validation"
    PROFILE_FAILED = "profile.failed"
    # crawl
    CRAWL_STARTED = "crawl.started"
    CRAWL_PAGE_DISCOVERED = "crawl.page.discovered"
    CRAWL_PAGE_SKIPPED = "crawl.page.skipped"
    CRAWL_FINISHED = "crawl.finished"
    # browser
    BROWSER_STARTED = "browser.started"
    BROWSER_PAGE_RENDERED = "browser.page.rendered"
    BROWSER_FORM_DISCOVERED = "browser.form.discovered"
    BROWSER_SCRIPT_DISCOVERED = "browser.script.discovered"
    BROWSER_API_DISCOVERED = "browser.api.discovered"
    BROWSER_ROUTE_DISCOVERED = "browser.route.discovered"
    BROWSER_FINISHED = "browser.finished"
    BROWSER_FAILED = "browser.failed"
    # framework
    FRAMEWORK_DETECTED = "framework.detected"
    FRAMEWORK_ROUTE_DISCOVERED = "framework.route.discovered"
    FRAMEWORK_FINISHED = "framework.finished"
    # engine
    ENGINE_STARTED = "engine.started"
    ENGINE_FINISHED = "engine.finished"
    ENGINE_FAILED = "engine.failed"
    ENGINE_SKIPPED = "engine.skipped"
    # finding
    FINDING_CREATED = "finding.created"
    FINDING_SUPPRESSED = "finding.suppressed"
    FINDING_ESCALATED = "finding.escalated"
    FINDING_CORRELATED = "finding.correlated"
    # wade
    WADE_STARTED = "wade.started"
    WADE_BASELINE_LOADED = "wade.baseline.loaded"
    WADE_CHANGE_DETECTED = "wade.change.detected"
    WADE_CONFIDENCE_CALCULATED = "wade.confidence.calculated"
    WADE_FINISHED = "wade.finished"
    # correlation
    CORRELATION_STARTED = "correlation.started"
    CORRELATION_CHAIN_CREATED = "correlation.chain.created"
    CORRELATION_SEVERITY_ESCALATED = "correlation.severity.escalated"
    CORRELATION_FINISHED = "correlation.finished"
    # report
    REPORT_STARTED = "report.started"
    REPORT_SECTION_GENERATED = "report.section.generated"
    REPORT_FINISHED = "report.finished"
    # persistence
    SAVE_STARTED = "save.started"
    SAVE_FINISHED = "save.finished"
    SAVE_FAILED = "save.failed"
    # data handoff
    HANDOFF_SNAPSHOT = "handoff.snapshot"


# High-frequency, per-item event types — only emitted at the FULL level.
HIGH_FREQUENCY: frozenset[EventType] = frozenset({
    EventType.CRAWL_PAGE_DISCOVERED, EventType.CRAWL_PAGE_SKIPPED,
    EventType.BROWSER_PAGE_RENDERED, EventType.BROWSER_FORM_DISCOVERED,
    EventType.BROWSER_SCRIPT_DISCOVERED, EventType.BROWSER_API_DISCOVERED,
    EventType.BROWSER_ROUTE_DISCOVERED, EventType.FRAMEWORK_ROUTE_DISCOVERED,
    EventType.FINDING_CREATED, EventType.FINDING_SUPPRESSED,
    EventType.WADE_CHANGE_DETECTED, EventType.REPORT_SECTION_GENERATED,
})

# Failure event types — emitted even at the ERRORS level.
FAILURE_TYPES: frozenset[EventType] = frozenset({
    EventType.SCAN_FAILED, EventType.SCAN_CANCELLED,
    EventType.PROFILE_FAILED, EventType.BROWSER_FAILED,
    EventType.ENGINE_FAILED, EventType.SAVE_FAILED,
})

# Always emitted at ERRORS+ (scan lifecycle context).
LIFECYCLE_TYPES: frozenset[EventType] = frozenset({
    EventType.SCAN_STARTED, EventType.SCAN_FINISHED,
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TelemetryEvent:
    event_type: EventType
    stage: Stage
    scan_id: str
    sequence: int
    status: Status = Status.OK
    job_id: str | None = None
    engine: str | None = None
    duration_ms: float | None = None
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "scan_id": self.scan_id,
            "job_id": self.job_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "stage": self.stage.value,
            "event_type": self.event_type.value,
            "engine": self.engine,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "inputs": dict(self.inputs),
            "outputs": dict(self.outputs),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "metadata": dict(self.metadata),
        }
