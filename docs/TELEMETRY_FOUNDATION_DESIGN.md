# WebHound Telemetry Foundation — Design (Phase 2)

**Status:** DESIGN ONLY — awaiting architecture-review approval. No implementation.
**Scope guardrail:** observability only. No change to detection, severity, suppression, WADE, correlation, or report logic.
**Author role:** Principal Architecture / Security / Detection / Observability / Backend / QA review.

---

## 1. Current Observability Audit (Step 1)

WebHound is **not** a blank slate. It already has a meaningful — but **aggregate, not event-level** — observability layer. The telemetry foundation must wrap these as *event sources*, not replace them.

| Capability | Where | What it gives us | Gap for telemetry |
|---|---|---|---|
| **Per-engine status** | `core/engine_tracker.py` → `EngineTracker.record_run/record_error/record_skip` → `build_statuses()` | One `EngineStatus` summary per engine per scan (name, category, status, findings_count, severity_breakdown, duration_ms, skipped_reason, error_message) | Summary only — no timestamps, no start/finish pair, no inputs/outputs |
| **EngineStatus model** | `models/engine_status.py` | Structured per-engine outcome | Not a timeline; one row per engine |
| **Scan context** | `core/scan_context.py` → `ScanContext` | `tracker`, `record_error()`, `snapshot()` (live progress: pages, findings, errors), `browser_discovery`, `framework_result` | `snapshot()` is logged, never persisted as an event stream |
| **Engine-run wrapper** | `orchestrator.py` `_record_engine_run` | Centralised timing + tracker recording around each engine | The single best **injection point** for `engine.started/finished/failed` events |
| **Scan telemetry** | `core/performance.py` → `ScanTelemetry.from_result()` | total_duration, slowest_engines, total_engine_ms | Derived post-hoc from the result; not a live recorder |
| **Perf metrics** | `core/performance_metrics.py` (Phase 17) | Normalised perf block from metadata | Reuse as the `scan.finished` payload |
| **Engine health** | `core/engine_health.py` (Phase 17) | Cross-scan health/silent-engine detection | Consumer of telemetry, not a source |
| **Structured logging + redaction** | `apps/api/platform/observability/structured_logging.py` (Phase 17) | `scan_log_record()` + `redact()` (secret-key + secret-value patterns) | **Reuse verbatim** as the telemetry redaction core (do not reinvent) |
| **Diagnostics persistence** | `apps/api/models/engine_diagnostic.py` → `EngineDiagnosticRecord` | Per-engine status persisted per scan | Precedent for the new `scanner_telemetry_events` table |
| **Diagnostics API** | `routers/scan_results.py` `GET /{id}/engine-diagnostics` | Per-engine status served to dashboard | Precedent for the new `/internal/scans/{id}/*` endpoints |
| **Rich metadata** | orchestrator → `scan_result.metadata` | coverage_summary, fetch_stats, crawl_duration_seconds, browser_pass, frameworks, advisor, security_graph_summary, wade_timeline, threat_correlations, security_stories | These ARE the per-stage outputs — telemetry snapshots reference them by key/count, never copy bodies |
| **Best-effort instrumentation** | orchestrator (~15 `try/except` + `logger.info/warning`) | Failures logged, scan never aborts | Logs are ephemeral + unstructured; telemetry makes them queryable |

**Conclusion:** ~70% of the *data* already exists; what's missing is a **timestamped, persisted, queryable event stream** + **stage handoff snapshots** + **finding/WADE/correlation decision events**. Build a thin recorder that consumes existing sources.

---

## 2. Telemetry Architecture (Step 2)

A dedicated, **side-effect-only** subsystem in the scanner package:

```
scanner/webhound/telemetry/
├── events.py       # Event dataclass + EventType/Stage/Status enums (the taxonomy)
├── schemas.py      # Pydantic/validation for event payloads (inputs/outputs shape)
├── redaction.py    # thin re-export/adapter over Phase-17 structured_logging.redact
├── recorder.py     # TelemetryRecorder: emit(), stage_snapshot(), context mgr; in-memory ring + sinks
├── counters.py     # cheap monotonic counters (pages, findings, suppressions…) per scan
├── filters.py      # sampling / level gating (off|errors|engines|full) + allowlist
├── exporters.py    # to audit_trace dict, to event list, to JSON sink
├── storage.py      # sink interface; NullSink (default), MetadataSink, (API) DBSink
├── retention.py    # pure retention policy (age/size caps) — applied by the API/worker
└── search.py       # in-memory query helpers (consumed by the internal API)
```

### Design principles
1. **Non-invasive.** The recorder is an optional `ctx.telemetry`. If absent/disabled, every emit is a no-op. The orchestrator never branches on telemetry results.
2. **Reuse, don't duplicate.** `EngineTracker` stays the source of truth for engine summaries; the recorder *also* emits `engine.started/finished` from the same `_record_engine_run` wrapper. `redact()` is reused from Phase 17.
3. **Bounded by construction.** Events store **counts, ids, hashes, domains, durations, categories** — never bodies, never findings objects. An in-memory ring buffer caps per-scan event count (default 5,000); overflow increments a dropped-counter.
4. **Default-off in the hot path.** `WEBHOUND_TELEMETRY_LEVEL=off|errors|engines|full` (default `engines`). `off` = recorder is a NullRecorder. Storage default = `MetadataSink` (folds a compact summary into `scan_result.metadata.telemetry`), so nothing new is required to start; the DB sink is opt-in.
5. **Same trust posture.** Telemetry is **not** customer-facing by default (mirrors the security-graph decision). It powers internal diagnostics / SOC.

### Data flow
```
engine/stage code → ctx.telemetry.emit(Event)  → [filters: level/sample]
                                                → [redaction.redact(payload)]
                                                → in-memory ring + counters
on scan end → exporters.to_audit_trace() / MetadataSink → scan_result.metadata.telemetry
(API/worker, opt-in) → DBSink → scanner_telemetry_events
```

---

## 3. Event Model (Step 3)

One immutable dataclass; all fields JSON-safe after redaction.

```python
@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str          # uuid4
    scan_id: str
    job_id: str | None
    sequence: int          # monotonic per scan (ordering without clock skew)
    timestamp: str         # ISO-8601 UTC
    stage: str             # Stage enum value (crawl, browser, engine, wade, …)
    event_type: str        # EventType enum value (engine.finished, …)
    engine: str | None     # engine name when stage == engine
    status: str            # ok | error | skipped | info
    duration_ms: float | None
    inputs: dict           # COUNTS + ids only (e.g. {"pages": 12})
    outputs: dict          # COUNTS + ids only (e.g. {"findings": 3, "suppressed": 1})
    warnings: list[str]    # short, redacted
    errors: list[str]      # error TYPE + redacted message (never stack w/ secrets)
    metadata: dict         # safe extras (band, confidence_label, change_type…)
```

- **`sequence`** guarantees deterministic ordering for replay even when timestamps collide.
- **`inputs`/`outputs`** are *contracts of counts*, validated by `schemas.py` — a code review check that no body/finding object is ever placed there.
- Every event passes through `redaction.redact()` before it lands in the ring.

---

## 4. Event Taxonomy (Step 4)

`EventType` (str enum) + `Stage` (str enum). Full catalog (matches the prompt; `*` = high-frequency, gated above `engines` level):

```
# scan        scan.started, scan.finished, scan.failed, scan.cancelled
# profile     profile.loaded, profile.validation, profile.failed
# crawl       crawl.started, crawl.page.discovered*, crawl.page.skipped*, crawl.finished
# browser     browser.started, browser.page.rendered*, browser.form.discovered*,
#             browser.script.discovered*, browser.api.discovered*,
#             browser.route.discovered*, browser.finished, browser.failed
# framework   framework.detected, framework.route.discovered*, framework.finished
# engine      engine.started, engine.finished, engine.failed, engine.skipped
# finding     finding.created*, finding.suppressed*, finding.escalated, finding.correlated
# wade        wade.started, wade.baseline.loaded, wade.change.detected*,
#             wade.confidence.calculated, wade.finished
# correlation correlation.started, correlation.chain.created,
#             correlation.severity.escalated, correlation.finished
# report      report.started, report.section.generated*, report.finished
# persistence save.started, save.finished, save.failed
# handoff     handoff.snapshot   (Step 6)
```

`*` events are emitted only at `WEBHOUND_TELEMETRY_LEVEL=full`; `engines` (default) emits start/finish/failed/skipped + handoff snapshots + scan lifecycle; `errors` emits only `*.failed` + `scan.*`.

---

## 5. Engine Telemetry Plan (Step 5)

Single injection point: `orchestrator._record_engine_run` already wraps every engine with timing + tracker. Add two emits there — `engine.started` (inputs) and `engine.finished|failed|skipped` (outputs) — so **all 15 engines are covered with one code change**, not 15.

Per engine, the standard `inputs`/`outputs` count contract (no engine-specific code; derived from the tracker accumulator + the engine's finding list):

| Field | Source | Example |
|---|---|---|
| inputs.received | pages/scripts/hosts handed to the engine | `{"pages": 12}` |
| inputs.ignored | in-scope minus processed (when the engine reports it) | `{"out_of_scope": 3}` |
| outputs.processed | items the engine actually evaluated | `{"paths": 47}` |
| outputs.findings | `len(engine findings)` | `{"findings": 4}` |
| outputs.suppressed | findings dropped by the engine's own gating | `{"suppressed": 23}` ← the catch-all-403 case becomes *visible* |
| errors | `error_message` from the accumulator | `["TimeoutError: …"]` |
| duration_ms | tracker accumulator | `148900.0` |
| metadata.decision | optional one-line reason an engine already computes | `"catch_all_403 suppressed"` |

Engines covered (no per-engine code): Headers, Cookies, TLS, DNS, Sensitive Paths, JavaScript, Threat Intel, Forms, API Discovery, Third-Party Domains, Framework Discovery, Vulnerable Libraries, Industry Intelligence, WADE, Correlation. *Decision-reason* enrichment (optional, later) is the only place per-engine hooks might be added — and only if the engine already computes the reason.

---

## 6. Data-Handoff Telemetry Plan (Step 6)

A `handoff.snapshot` event at each pipeline boundary, emitted by the orchestrator (it already has the data at these points). Each snapshot is **counts only**, pulled from existing structures (`ctx`, `scan_result`, `metadata`):

Boundaries: after-crawl, after-browser, after-framework, before-engines, after-engines, before-wade, after-wade, before-correlation, after-correlation, before-report, before-save, before-api (API layer), before-dashboard (frontend, optional later).

Tracked counts per snapshot:
`pages, forms, scripts, api_endpoints, routes, third_party_domains, frameworks, industry_data, findings, suppressed_findings, errors`.

This is the deliverable that makes the *original audit problem impossible to recur*: a count that drops to 0 between two snapshots is now a visible, queryable event ("third_party_domains: 1 → 0 between after-engines and before-report").

---

## 7. Redaction Rules (Step 7)

**Reuse Phase-17 `structured_logging.redact()`** (already battle-tested + unit-covered): secret-key substrings (password/token/secret/cookie/authorization/api_key/bearer/jwt…) and secret-value patterns (`sk_live_`, `whsec_`, `Bearer …`, JWT, `re_…`). `telemetry/redaction.py` is a thin adapter that adds telemetry-specific rules:

- **Allowlist of value types:** counts (int), durations (float), enum strings (status/stage/band/category), hashes (sha256[:16]), ids (uuid), hostnames (already public). Anything not on the allowlist in `inputs`/`outputs`/`metadata` is dropped, not stored.
- **Never store:** request/response bodies, cookie/JWT/auth values, API keys, Stripe/Railway/Vercel/Cloudflare secrets, raw finding evidence, PII, full URLs with query strings (store **path only**, query-stripped + length).
- **Hash, don't store:** when a value must be correlated but not revealed (e.g. an inline-script identity), store `sha256(value)[:16]`.
- **Enforcement:** `schemas.py` validates event payloads in tests; a CI test asserts a battery of secret-shaped inputs round-trips to `<redacted>`/dropped.

---

## 8. Storage Model (Step 8)

```sql
CREATE TABLE scanner_telemetry_events (
    id           UUID PRIMARY KEY,
    scan_id      VARCHAR(255) NOT NULL,
    job_id       UUID NULL,
    sequence     INTEGER NOT NULL,
    event_type   VARCHAR(48) NOT NULL,
    stage        VARCHAR(32) NOT NULL,
    engine       VARCHAR(64) NULL,
    status       VARCHAR(16) NOT NULL,
    duration_ms  DOUBLE PRECISION NULL,
    inputs       JSONB NULL,
    outputs      JSONB NULL,
    metadata     JSONB NULL,
    error        TEXT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Indexes:
- `(scan_id, sequence)` — timeline reconstruction (primary access path).
- `(scan_id, event_type)` — per-type filter.
- `(engine, created_at)` — cross-scan engine queries (feeds `engine_health`).
- `(event_type, created_at)` WHERE `status='error'` — failure surface.
- `(created_at)` — retention sweeps.

**Storage posture (critical concern):** a `full`-level scan can emit thousands of events. Therefore:
- DB persistence is **opt-in** (`WEBHOUND_TELEMETRY_PERSIST=1`) and **default-off**. Default sink = `MetadataSink` (a compact per-stage summary folded into `scan_result.metadata.telemetry`, ~2-5 KB).
- When persisting, the worker writes events in **one batched insert** after the scan (not per-event round-trips).
- Migration follows the additive/idempotent pattern (cf. `0032_website_groups`); new table only, **no change to existing tables**.

---

## 9. Audit Trace Specification (Step 9)

`exporters.to_audit_trace(recorder) -> dict` produces a single `audit_trace.json` (the black-box recorder) reconstructable after any scan:

```json
{
  "scan_id": "...", "job_id": "...", "profile": "deep",
  "started_at": "...", "finished_at": "...", "status": "completed",
  "timeline": [ {sequence, timestamp, stage, event_type, engine, status, duration_ms, inputs, outputs} ],
  "handoffs": { "after_crawl": {counts…}, "after_engines": {counts…}, … },
  "engines": { "<name>": {duration_ms, findings, suppressed, status, decision} },
  "findings": { "created": N, "suppressed": N, "escalated": N, "correlated": N },
  "wade": { "baseline_loaded": bool, "changes_detected": N, "compared_to_previous": bool },
  "correlation": { "chains_created": N, "escalations": N },
  "report": { "sections": [...] },
  "persistence": { "status": "...", "duration_ms": N },
  "api": { "served_at": "...", "fields": [...] },
  "dropped_events": N,
  "telemetry_level": "engines"
}
```

Replay = iterate `timeline` by `sequence`; every count delta is attributable to a stage. References existing metadata by key — never duplicates finding bodies.

---

## 10. Search Design (Step 10)

`search.py` provides in-memory predicates over a loaded event list (API loads by `scan_id` then filters); the same predicates map 1:1 to SQL `WHERE` clauses when persisted. Search axes: `scan_id, domain (hostname), engine, event_type, status, error (substring), duration (min/max), finding (type), timestamp (range)`. Returns events ordered by `sequence`. No full-text engine required — JSONB + the composite indexes in §8 cover every axis.

---

## 11. Internal API Design (Step 11)

New router `apps/api/routers/internal_telemetry.py` (admin-guarded, mirrors existing `internal_*` routers + `is_admin` checks):

| Endpoint | Returns |
|---|---|
| `GET /internal/scans/{id}/timeline` | ordered events (sequence, stage, type, engine, status, duration) |
| `GET /internal/scans/{id}/events?type=&engine=&status=` | filtered events (§10 axes) |
| `GET /internal/scans/{id}/trace` | the full `audit_trace.json` (§9) |
| `GET /internal/scans/{id}/diagnostics` | engine health + handoff deltas + dropped count |

Auth: admin-only (telemetry is internal). Reads from `scanner_telemetry_events` when persisted, else from `scan_result.metadata.telemetry` (degraded: summary + handoffs, no full timeline).

---

## 12. Test Plan (Step 12)

A `FakeSink`/`MemoryRecorder` captures events in-process; tests assert events fire **without** asserting scanner behavior (scope guard). Regression tests:

1. `scan.started` + `scan.finished` bracket every scan; `sequence` monotonic.
2. `crawl.started/finished` + page counts match `urls_crawled`.
3. `browser.started` + (`finished` when enabled / `failed|skipped` when deferred — the RC1 case is now an *event*).
4. `framework.detected` fires with the primary framework.
5. `engine.started/finished` fires for **every** engine in `engine_diagnostics` (parity test: telemetry engines == tracker engines).
6. `engine.skipped`/`outputs.suppressed` captures the catch-all-403 suppression count.
7. `wade.started/finished` + `baseline.loaded` reflects `wade_compared_to_previous`.
8. `correlation.chain.created` count == cluster findings count.
9. `report.finished` + `save.finished` fire.
10. `handoff.snapshot` emitted at each boundary; a synthetic count-drop is detectable.
11. **Redaction:** a battery of secret-shaped payloads → `<redacted>`/dropped (reuses Phase-17 redaction tests + telemetry allowlist).
12. **No-op guarantee:** with `WEBHOUND_TELEMETRY_LEVEL=off`, zero events, zero behavior change, scan result byte-identical.
13. **Performance:** `full`-level overhead on a fixture scan < target budget (see Risks).

---

## Conflicts, Risks, Performance & Storage (required gate analysis)

### Conflicts with current architecture
- **EngineTracker overlap.** `engine.finished` events and `EngineStatus` summaries describe the same thing. *Resolution:* the recorder **derives** engine events from the tracker accumulator at the existing `_record_engine_run` site — single source, no divergence. No change to `EngineStatus`/`EngineDiagnosticRecord`.
- **`ScanTelemetry`/`performance_metrics` overlap.** Both compute durations. *Resolution:* `scan.finished` payload **calls** `extract_performance_metrics()` rather than recomputing.
- **`metadata.telemetry` vs existing metadata keys.** Telemetry references existing keys by name/count; it never copies `frameworks`/`advisor`/etc. bodies. No key collision (`telemetry` is new).
- **Two redaction implementations risk.** Avoided by reusing Phase-17 `redact()`.

### Risks
- **Scope creep into behavior.** Mitigation: the no-op test (#12) asserts byte-identical results with telemetry off; recorder is pure side-effect.
- **Event-contract leakage** (someone puts a finding object in `outputs`). Mitigation: `schemas.py` validation + CI redaction battery (#11).
- **Sequence vs async.** The pipeline is mostly sequential, but browser/engine passes have concurrency. Mitigation: `sequence` is an atomic counter on the recorder; events are still totally ordered by emit time.
- **Cardinality explosion** at `full` (per-page/per-script events). Mitigation: ring-buffer cap + `dropped_events` counter + level gating; `full` is opt-in for debugging, never default.

### Performance concerns
- Target: **< 2% wall-clock overhead at default (`engines`) level**, **< 5% at `full`**. Each emit is a dict build + redact + append (O(1)); no I/O in the hot path (sinks flush at scan end).
- Redaction is regex over small dicts — measured in Phase 17 as sub-millisecond; acceptable at `engines` (tens of events/scan). `full` (thousands) needs the ring cap to bound it — hence #13.
- **No per-event DB writes.** Persistence is a single batched insert post-scan, off the critical path.

### Storage concerns
- Default `MetadataSink` adds ~2-5 KB/scan to an existing JSON column — negligible.
- Opt-in DB: at `engines` level ~30-60 rows/scan; at `full` potentially thousands. Retention (`retention.py`) caps by age (default 30 days) + per-scan row cap; the worker sweeps. Hobby-plan Postgres (4.9 GB volume) → keep DB persistence off by default; enable per-investigation.

### Migration & rollout
1. Land `telemetry/` package + recorder with **NullRecorder default** (zero behavior change) — mergeable immediately.
2. Wire emits at the 3 choke points (`_record_engine_run`, stage boundaries, scan lifecycle) behind the level gate.
3. `MetadataSink` on by default (summary only).
4. DB sink + migration + internal API as a **separate** opt-in slice.
5. Frontend SOC views consume the internal API later (out of scope here).

---

## Open questions for review approval
1. **Default level** — confirm `engines` (start/finish/handoff/lifecycle) is the right default vs `errors` (leanest).
2. **DB persistence default** — recommend **off** on hobby Postgres; confirm.
3. **Customer exposure** — recommend internal-only (admin) like the security graph; confirm telemetry is never in the customer report.
4. **Decision-reason enrichment** — approve the *only* per-engine hooks (optional `metadata.decision`) or defer entirely to keep this phase zero-touch on engines.
```
