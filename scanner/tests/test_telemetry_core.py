# WebHound — tests/test_telemetry_core.py
# Phase-2 telemetry foundation: recorder, level gating, redaction,
# exporters. Pure unit tests — no scanner involved.

from __future__ import annotations

from webhound.telemetry import (
    EventType,
    NullRecorder,
    Stage,
    Status,
    TelemetryRecorder,
    build_recorder,
    errors_only,
    redact,
    resolve_level,
    safe_payload,
    search_events,
    slowest,
    to_audit_trace,
    to_event_list,
    to_metadata_summary,
)


# ---------------------------------------------------------------------------
# Level resolution + gating
# ---------------------------------------------------------------------------


def test_resolve_level_default_and_invalid(monkeypatch) -> None:
    monkeypatch.delenv("WEBHOUND_TELEMETRY_LEVEL", raising=False)
    assert resolve_level() == "engines"
    assert resolve_level("FULL") == "full"
    assert resolve_level("nonsense") == "engines"   # falls back to default


def test_off_level_is_null_recorder() -> None:
    rec = build_recorder("s1", level="off")
    assert isinstance(rec, NullRecorder)
    rec.emit(EventType.SCAN_STARTED, Stage.SCAN)
    assert rec.event_count == 0


def test_errors_level_only_failures_and_lifecycle() -> None:
    rec = TelemetryRecorder("s1", level="errors")
    rec.emit(EventType.SCAN_STARTED, Stage.SCAN)        # lifecycle → kept
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE)   # not failure → gated
    rec.emit(EventType.ENGINE_FAILED, Stage.ENGINE)     # failure → kept
    types = {e.event_type for e in rec.events()}
    assert EventType.SCAN_STARTED in types
    assert EventType.ENGINE_FAILED in types
    assert EventType.ENGINE_FINISHED not in types


def test_engines_level_drops_high_frequency() -> None:
    rec = TelemetryRecorder("s1", level="engines")
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE)        # kept
    rec.emit(EventType.FINDING_CREATED, Stage.FINDING)       # high-freq → gated
    rec.emit(EventType.CRAWL_PAGE_DISCOVERED, Stage.CRAWL)   # high-freq → gated
    types = {e.event_type for e in rec.events()}
    assert EventType.ENGINE_FINISHED in types
    assert EventType.FINDING_CREATED not in types


def test_full_level_keeps_everything() -> None:
    rec = TelemetryRecorder("s1", level="full")
    rec.emit(EventType.FINDING_CREATED, Stage.FINDING)
    rec.emit(EventType.CRAWL_PAGE_DISCOVERED, Stage.CRAWL)
    assert rec.event_count == 2


# ---------------------------------------------------------------------------
# Sequencing + bounding
# ---------------------------------------------------------------------------


def test_sequence_monotonic() -> None:
    rec = TelemetryRecorder("s1", level="full")
    for _ in range(5):
        rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE)
    seqs = [e.sequence for e in rec.events()]
    assert seqs == [1, 2, 3, 4, 5]


def test_ring_buffer_bounds_and_counts_dropped() -> None:
    rec = TelemetryRecorder("s1", level="full", ring_size=10)
    for _ in range(25):
        rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE)
    assert rec.event_count == 10
    assert rec.dropped_events >= 15


def test_emit_never_raises() -> None:
    rec = TelemetryRecorder("s1", level="full")
    # A non-serialisable object in metadata must not blow up the scan.
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE,
             metadata={"weird": object()})
    assert rec.event_count == 1


# ---------------------------------------------------------------------------
# Redaction / allowlist
# ---------------------------------------------------------------------------


def test_redact_secrets() -> None:
    out = redact({"password": "x", "host": "cdn.test",
                  "auth": "Bearer abc.def"})
    assert out["password"] == "<redacted>"
    assert out["auth"] == "<redacted>"
    assert out["host"] == "cdn.test"


def test_safe_payload_keeps_counts_drops_freeform() -> None:
    out = safe_payload({
        "pages": 12, "duration_ms": 4.5, "host": "cdn.test",
        "third_party_domains": ["a.com", "b.com"],      # list → count
        "raw_body": "secret-ish long free text content",  # free str → len
        "api_key": "sk_live_ABC123",                     # secret → redacted
    })
    assert out["pages"] == 12
    assert out["host"] == "cdn.test"
    assert out["third_party_domains"] == {"count": 2}
    assert out["raw_body"] == {"len": len("secret-ish long free text content")}
    assert out["api_key"] == "<redacted>"


def test_safe_payload_strips_query_string() -> None:
    out = safe_payload({"path": "/checkout?token=abc123&id=5"})
    assert out["path"] == "/checkout"


def test_event_payloads_are_redacted_on_emit() -> None:
    rec = TelemetryRecorder("s1", level="full")
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE,
             outputs={"findings": 3, "authorization": "Bearer leak"})
    e = rec.events()[0]
    assert e.outputs["findings"] == 3
    assert e.outputs["authorization"] == "<redacted>"


# ---------------------------------------------------------------------------
# Handoff snapshots + exporters
# ---------------------------------------------------------------------------


def test_stage_snapshot_records_handoff() -> None:
    rec = TelemetryRecorder("s1", level="engines")
    rec.stage_snapshot("after_engines", {"findings": 42, "third_party_domains": 1})
    assert rec.handoffs["after_engines"]["findings"] == 42
    # Also emitted as an event.
    assert any(e.event_type is EventType.HANDOFF_SNAPSHOT for e in rec.events())


def test_audit_trace_and_summary_shape() -> None:
    rec = TelemetryRecorder("s1", job_id="j1", level="full")
    rec.emit(EventType.SCAN_STARTED, Stage.SCAN)
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE, engine="headers",
             duration_ms=12.0, outputs={"findings": 2, "suppressed": 0})
    rec.emit(EventType.CORRELATION_CHAIN_CREATED, Stage.CORRELATION)
    rec.stage_snapshot("after_engines", {"findings": 2})
    rec.emit(EventType.SCAN_FINISHED, Stage.SCAN)

    trace = to_audit_trace(rec)
    assert trace["scan_id"] == "s1" and trace["job_id"] == "j1"
    assert len(trace["timeline"]) == rec.event_count
    assert trace["engines"]["headers"]["findings"] == 2
    assert trace["correlation"]["chains_created"] == 1
    assert "after_engines" in trace["handoffs"]

    summary = to_metadata_summary(rec)
    assert summary["level"] == "full"
    assert summary["engines"]["headers"]["duration_ms"] == 12.0
    assert "nodes" not in summary            # no raw dump
    assert "timeline" not in summary         # summary != trace


def test_search_events_axes() -> None:
    rec = TelemetryRecorder("s1", level="full")
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE, engine="headers",
             duration_ms=5.0)
    rec.emit(EventType.ENGINE_FAILED, Stage.ENGINE, engine="tls",
             status=Status.ERROR, duration_ms=50.0, errors=["TimeoutError: x"])
    rec.emit(EventType.ENGINE_FINISHED, Stage.ENGINE, engine="dns",
             duration_ms=200.0)
    ev = to_event_list(rec)

    assert len(search_events(ev, engine="headers")) == 1
    assert len(search_events(ev, status="error")) == 1
    assert len(errors_only(ev)) == 1
    assert search_events(ev, error_contains="timeout")[0]["engine"] == "tls"
    assert len(search_events(ev, min_duration_ms=100)) == 1
    assert slowest(ev, 1)[0]["engine"] == "dns"
    # Results stay in sequence order.
    seqs = [e["sequence"] for e in search_events(ev, stage="engine")]
    assert seqs == sorted(seqs)


def test_timed_span_records_duration_and_error() -> None:
    rec = TelemetryRecorder("s1", level="full")
    with rec.timed(EventType.ENGINE_FINISHED, Stage.ENGINE, engine="tls"):
        pass
    e = rec.events()[0]
    assert e.duration_ms is not None and e.status is Status.OK

    try:
        with rec.timed(EventType.ENGINE_FINISHED, Stage.ENGINE, engine="dns"):
            raise ValueError("boom")
    except ValueError:
        pass
    failed = rec.events()[1]
    assert failed.status is Status.ERROR
    assert any("boom" in err for err in failed.errors)
