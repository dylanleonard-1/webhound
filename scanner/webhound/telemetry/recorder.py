# WebHound — scanner/webhound/telemetry/recorder.py
# Phase-2 telemetry recorder. A thin, side-effect-only event sink the
# orchestrator/stages emit into. If disabled (level=off) it is a
# NullRecorder and every method is a no-op, guaranteeing zero behaviour
# change. No I/O in the hot path — events accumulate in a bounded ring
# buffer and are exported at scan end.

from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Any

from webhound.telemetry.events import (
    FAILURE_TYPES,
    HIGH_FREQUENCY,
    LIFECYCLE_TYPES,
    EventType,
    Stage,
    Status,
    TelemetryEvent,
)
from webhound.telemetry.redaction import safe_payload

logger = logging.getLogger(__name__)

# Level ordering: off < errors < engines < full.
_LEVELS = ("off", "errors", "engines", "full")
_DEFAULT_LEVEL = "engines"
_DEFAULT_RING = 5000


def resolve_level(explicit: str | None = None) -> str:
    level = (explicit or os.getenv("WEBHOUND_TELEMETRY_LEVEL", _DEFAULT_LEVEL)
             or _DEFAULT_LEVEL).strip().lower()
    return level if level in _LEVELS else _DEFAULT_LEVEL


class TelemetryRecorder:
    """Collects telemetry events for one scan. Level-gated, bounded, and
    pure side-effect — nothing it returns is consumed by scan logic."""

    def __init__(
        self,
        scan_id: str,
        *,
        job_id: str | None = None,
        level: str | None = None,
        ring_size: int = _DEFAULT_RING,
    ) -> None:
        self.scan_id = scan_id
        self.job_id = job_id
        self.level = resolve_level(level)
        self._events: deque[TelemetryEvent] = deque(maxlen=ring_size)
        self._seq = 0
        self._dropped = 0
        self.handoffs: dict[str, dict[str, Any]] = {}

    @property
    def enabled(self) -> bool:
        return self.level != "off"

    @property
    def dropped_events(self) -> int:
        # Ring overflow + gated-out high-frequency events both "drop".
        return self._dropped + max(
            0, (self._seq - len(self._events)) if self._events.maxlen else 0)

    # ------------------------------------------------------------------
    # Level gating
    # ------------------------------------------------------------------

    def _passes_level(self, event_type: EventType) -> bool:
        lvl = self.level
        if lvl == "off":
            return False
        if lvl == "full":
            return True
        if lvl == "errors":
            return (event_type in FAILURE_TYPES
                    or event_type in LIFECYCLE_TYPES)
        # engines: everything except per-item high-frequency events.
        return event_type not in HIGH_FREQUENCY

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    def emit(
        self,
        event_type: EventType,
        stage: Stage,
        *,
        status: Status = Status.OK,
        engine: str | None = None,
        duration_ms: float | None = None,
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record one event. Never raises — telemetry failures must never
        break a scan."""
        try:
            if not self._passes_level(event_type):
                self._dropped += 1
                return
            self._seq += 1
            self._events.append(TelemetryEvent(
                event_type=event_type, stage=stage, scan_id=self.scan_id,
                job_id=self.job_id, sequence=self._seq, status=status,
                engine=engine, duration_ms=duration_ms,
                inputs=safe_payload(inputs), outputs=safe_payload(outputs),
                warnings=[str(w)[:256] for w in (warnings or [])],
                errors=[str(e)[:256] for e in (errors or [])],
                metadata=safe_payload(metadata)))
        except Exception:  # noqa: BLE001 — telemetry is best-effort
            logger.debug("telemetry emit failed", exc_info=True)

    def stage_snapshot(self, label: str, counts: dict[str, Any]) -> None:
        """Record a data-handoff snapshot (counts only) at a pipeline
        boundary, and stash it for the audit trace's handoff map."""
        safe = safe_payload(counts)
        self.handoffs[label] = safe
        self.emit(EventType.HANDOFF_SNAPSHOT, Stage.HANDOFF,
                  status=Status.INFO, metadata={"boundary": label},
                  outputs=safe)

    # ------------------------------------------------------------------
    # Timing helper (context manager)
    # ------------------------------------------------------------------

    def timed(self, event_type_finished: EventType, stage: Stage, **kw):
        return _TimedSpan(self, event_type_finished, stage, kw)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def events(self) -> list[TelemetryEvent]:
        return list(self._events)

    @property
    def event_count(self) -> int:
        return len(self._events)


class _TimedSpan:
    def __init__(self, rec: TelemetryRecorder, et: EventType, stage: Stage,
                 kw: dict[str, Any]) -> None:
        self._rec, self._et, self._stage, self._kw = rec, et, stage, kw
        self._t0 = 0.0

    def __enter__(self) -> "_TimedSpan":
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        dur = (time.perf_counter() - self._t0) * 1000.0
        status = Status.ERROR if exc_type else self._kw.pop("status", Status.OK)
        errs = ([f"{exc_type.__name__}: {exc}"] if exc_type else
                self._kw.pop("errors", None))
        self._rec.emit(self._et, self._stage, status=status,
                       duration_ms=round(dur, 2), errors=errs, **self._kw)
        return False  # never suppress the real exception


class NullRecorder(TelemetryRecorder):
    """A recorder that records nothing — used when telemetry is off so the
    orchestrator can call ctx.telemetry unconditionally."""

    def __init__(self) -> None:
        super().__init__(scan_id="", level="off", ring_size=1)

    def emit(self, *a: Any, **k: Any) -> None:  # noqa: D401
        return

    def stage_snapshot(self, *a: Any, **k: Any) -> None:
        return


def build_recorder(
    scan_id: str, *, job_id: str | None = None, level: str | None = None,
) -> TelemetryRecorder:
    """Factory: a real recorder when enabled, else a NullRecorder."""
    lvl = resolve_level(level)
    if lvl == "off":
        return NullRecorder()
    return TelemetryRecorder(scan_id, job_id=job_id, level=lvl)
