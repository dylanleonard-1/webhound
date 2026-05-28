# WebHound Internal Operations Platform (`/control`)

The private SOC / command center used to operate the company — distinct from the
public customer dashboard. This documents the architecture, what's built (Phase 1),
and the phased roadmap for the remaining feature areas.

---

## Architecture decisions

**Built on the existing FastAPI + Postgres + Next.js stack — NOT Supabase.**
- The SOC must observe **live production data** (users, scans, findings, billing)
  that already lives in the production Postgres behind the FastAPI API. A parallel
  Supabase instance would fragment auth and data and require constant sync.
- **Auth reuses existing Google OAuth + JWT**, with `admin_emails` already
  auto-promoting the owner. We layered RBAC on top rather than introducing a
  second identity system.
- **`/control`** (and `/admin` alias) live as a hidden, RBAC-gated route group in
  the existing Next.js app. The **API (`/internal/*`) is the real security
  boundary** (returns 403 to non-staff); the route group hides the surface and
  redirects unauthorized users. _Future option: split `/control` into a separate
  Vercel deployment so the internal bundle never ships to customers._
- **Realtime:** Phase 1 uses polling (10s). WebSocket/SSE is the next step for the
  live activity feed and alerts (see Realtime below).

### RBAC model
`AdminRole` (low→high): `none < read_only < {billing, support, developer} < analyst
< admin < super_admin`, ranked in `ROLE_RANK`. `require_admin(min_role)` gates each
route; `super_admin` satisfies everything. Customers are `none`. `admin_emails`
accounts (e.g. the owner) are auto-promoted to `super_admin` on startup + via the
0017 migration backfill.

### Audit
`admin_audit_logs` is an append-only trail (actor, action, target, detail JSONB,
ip, request_id, timestamp). `record_action()` is the write helper; the Command
Center surfaces the recent feed. **All future privileged mutations must call it.**

---

## Phase 1 — DELIVERED & verified in production

- **RBAC**: `AdminRole` + hierarchy, `users.admin_role`, `require_admin` dependency.
  `dmleonard5125@gmail.com` confirmed `super_admin`; a customer account confirmed
  `403` on `/internal/*`.
- **Audit**: `admin_audit_logs` table + `record_action()` helper.
- **Migration 0017** applied in prod (schema_revision=0017).
- **Global Command Center** (`/internal/command-center`) returning **real live
  data**: scans (queued/running/failed+completed 24h, avg duration), users
  (total/paid/new 7d), billing (active subs, MRR, ARR), infra (DB/Redis/queue
  depth/worker liveness/Stripe). Worker liveness via a Redis heartbeat stamp.
- **`/control` UI**: hidden RBAC-gated route group, live metric cards, infra health
  pills, 24h scan-activity chart, admin activity feed; `/admin` alias.

> **Known limitation:** Command Center MRR is *list-price* MRR from the local
> `subscriptions` table — it does not yet net out Stripe coupons/discounts. The
> Billing Ops Center (Phase 4) should pull true MRR from Stripe.

---

## Phase 2 — Scan & Engine Ops — DELIVERED

- **Scan Operations Center** (`/internal/scans`): list/search/filter (status,
  profile, URL/owner email) with pagination, joined to website + owner email;
  `/internal/scans/{id}` detail with per-engine diagnostics.
- **Operate** (ANALYST+): `POST /internal/scans/{id}/cancel` (reuses
  `cancel_scan_job` + best-effort Celery `revoke(terminate=True)`, audited),
  `POST /internal/scans/{id}/rescan` (admin-scoped `create_scan_job` + enqueue,
  audited with origin scan id). READ_ONLY+ can view; mutations require ANALYST.
- **Engine reliability scorecards** (`/internal/engines`): per `engine_name`
  runs / failed / skipped / failure-rate / empty-result-rate / avg duration /
  reliability % (share of runs that neither failed nor skipped), from
  `engine_diagnostics`. No schema change — derived from existing diagnostics.
- **`/control` UI**: tabbed nav (Command Center · Scan Ops · Engines); Scan Ops
  table with filters, detail drawer + cancel/rescan (gated by role); Engines
  scorecard grid. Both poll for live data.

> Deferred from the original Phase 2 sketch: an `engines` registry table +
> maintenance-mode toggle. Scorecards are computed from `engine_diagnostics`
> directly, so the registry isn't required yet; add it when per-engine config
> (maintenance flag, version pinning) is needed.

## Phase 3 — SOC Alerting + Realtime — DELIVERED

- **Schema (migration 0018)**: `alerts` (dedup_key unique, source, severity,
  status, target, JSONB detail, occurrences, first/last_seen, ack/resolve
  metadata, assignee FK users SET NULL), `alert_comments` (CASCADE,
  human/status_change/system kinds — the per-alert timeline).
- **Service** (`apps/api/services/alerts.py`): `upsert_alert(dedup_key, …)`
  dedups recurring conditions onto one row (bumps `occurrences` + `last_seen`,
  latest severity/title wins). `auto_resolve(dedup_key, note)` closes the open
  alert when the condition clears — used for health-style sources. Recurrence
  of a resolved alert re-opens it with a system timeline entry. Each lifecycle
  transition writes a timeline comment. Mutations are best-effort published to
  the Redis pub/sub channel `webhound:alerts:events`.
- **Evaluator** (`worker/alert_tasks.evaluate_alerts`, beat: every 5 min):
  derives alerts from observable state — failed scans (last 30 min, deduped
  by job id), engine reliability degradation (≥50% failure rate over 7d,
  ≥5 runs), worker liveness (heartbeat > 15 min stale), queue backup
  (depth ≥ 50 warn, ≥ 200 critical). Health sources auto-resolve when the
  condition clears.
- **API** (`/internal/alerts*`, RBAC-gated + audited):
  - `GET /internal/alerts` (READ_ONLY+) — list/filter by status/severity/source, paginated
  - `GET /internal/alerts/summary` — open counts by severity (for the nav badge)
  - `GET /internal/alerts/{id}` — detail + timeline
  - `POST /internal/alerts/{id}/{ack,resolve,assign,comment}` (ANALYST+)
  - `GET /internal/stream` — SSE pub/sub fan-out for realtime UI updates
- **`/control` UI**: Alerts nav tab with a live red badge (open count), a
  global LIVE pill driven by SSE, single shared event stream surfaced via
  `useControlEvents()` for any page to subscribe to; `/control/alerts` page
  with severity-colored queue, filters, detail drawer (timeline + ack/resolve
  + inline comment composer), role-gated actions.
- **Tests** (`apps/api/tests/test_alerts.py`): service dedup, auto-resolve +
  recurrence re-open, ack→resolve timeline, end-to-end API list/summary/
  detail/resolve/comment via an injected super_admin client, plus a 403
  check for customers.

> Deferred from the original Phase 3 sketch: a separate `incidents` table
> (multi-alert grouping) and a `notifications` outbound bridge (email/Slack
> from alerts). Phase 1's `notifications` model already exists; wire it next
> when paging staff via email/Slack becomes a requirement.

## Phase 4 — Customer + Billing Ops — DELIVERED

- **Schema (migration 0019)**: `users.last_login_at` (stamped on password and
  OAuth login), `users.banned_at` + `users.banned_reason` (suspend metadata),
  new `internal_notes` table (free-form staff notes keyed by `(target_type,
  target_id)`).
- **JWT force-logout** (`apps/api/security.py`): Redis denylist keyed
  `auth:denylist:{user_id}` with TTL = JWT expiry. `get_current_user` consults
  it on every request, so suspending or force-logging-out a user invalidates
  every outstanding token immediately. Best-effort: if Redis is unreachable
  the check falls open and the durable `is_active=False` flag still blocks
  the suspended user on the next DB read.
- **Customer Ops service** (`services/customers.py`): paginated search
  (email/name/company + plan + status: active/suspended/staff), detail
  aggregator (websites/scans/last-scan/failed-30d/subscription history),
  suspend/reactivate/force-logout, plan override (manual, not synced to
  Stripe), internal-note CRUD.
- **Customer Ops API** (`/internal/customers*`, all audited):
  - `GET /internal/customers` (READ_ONLY+) — search + filter
  - `GET /internal/customers/{id}` — detail
  - `POST /internal/customers/{id}/{suspend,reactivate,force-logout,plan}` (ADMIN)
  - `GET /internal/customers/{id}/notes` (READ_ONLY+) — list
  - `POST /internal/customers/{id}/notes` (SUPPORT+) — add
  - `DELETE /internal/notes/{id}` (ADMIN) — never lose timeline by accident
- **Billing Ops API** (`/internal/billing*`, BILLING+ role):
  - `GET /internal/billing/metrics` — **true MRR/ARR from Stripe** (pages
    through `Subscription.list(status=active|trialing)`, nets recurring item
    amounts × interval, applies the subscription's coupon `percent_off`/
    `amount_off`), past-due count, failed-payment count from `Event.list
    type=invoice.payment_failed` last 24h, plus local sanity counts.
    Replaces Phase 1's list-price approximation.
  - `GET /internal/billing/subscriptions` — local mirror joined to user email
  - `GET /internal/billing/events` — recent Stripe events (webhook delivery
    health proxy). Every Stripe call runs in a thread and degrades its own
    tile on failure.
- **`/control` UI**: new Customers + Billing nav tabs; `/control/customers`
  with search, plan/status filters, detail drawer (aggregate cards, subs
  list, role-gated suspend/reactivate/force-logout/plan-override + notes
  timeline with inline composer); `/control/billing` with MRR/ARR/past-due/
  failed-pay tiles, filterable subscriptions table, recent-events log with
  LIVE/TEST mode badges.
- **Tests** (`tests/test_customers.py`, 9 tests passing): service search
  filters by status + plan, suspend/reactivate clears all metadata, detail
  aggregator handles empty + missing, note CRUD ordering; API list/detail/
  suspend/cannot-suspend-self/RBAC matrix (READ_ONLY blocked from mutations,
  SUPPORT can add notes but not delete, ADMIN can delete + change plan).

## Phase 5 — Fraud & Abuse — DELIVERED

- **Schema (migration 0020)**: `abuse_flags` (dedup_key unique per subject,
  score + severity, status pending/dismissed/banned, JSONB reasons + detail,
  occurrences, ack/resolve metadata, FK users SET NULL); `ip_device_fingerprints`
  ((user_id, ip, ua) unique, occurrences, first/last_seen).
- **Login fingerprinting**: every successful password + Google + GitHub login
  upserts a `(user, ip, user_agent)` row used by the diversity signals.
- **Scoring engine** (`services/fraud.py`): independent signals each contribute
  a weight, total ≥ 30 → flag. Signals:
  - **excessive_scans** (≥50 in 24h, weight 30)
  - **failed_payments** (past_due/unpaid/incomplete_expired sub, weight 20)
  - **auth_failures** (≥5 in Redis `auth:fail:` counter or `auth:lock:` set, weight 25)
  - **many_ips** (≥5 distinct IPs in 7d, weight 15)
  - **many_user_agents** (≥4 distinct UAs in 7d, weight 10)
  - **high_fail_rate** (≥50% failed of ≥10 scans in 7d, weight 15)
  Severity = critical (≥80) / high (≥50) / medium (≥30).
- **Evaluator beat task** (`worker.fraud_tasks.evaluate_abuse`, every 15 min):
  cheap aggregate queries pick candidates (high scan volume, payment problems,
  IP/UA diversity), each is scored, flags are upserted; **cleared signals
  auto-dismiss the pending flag**.
- **API** (`/internal/abuse/*`, all audited):
  - `GET /flags` (READ_ONLY+) — list/filter by status/severity, paginated
  - `GET /summary` — pending counts by severity (nav badge)
  - `GET /flags/{id}` — detail enriched with subject email + active flag
  - `POST /flags/{id}/dismiss` (ANALYST+) with optional note
  - `POST /flags/{id}/ban` (ADMIN) — promotes to a real user suspension via
    `customers.suspend` (which also force-logs-out via the JWT denylist) and
    marks the flag `banned`. Self-ban blocked.
  - `POST /evaluate/{user_id}` (ANALYST+) — ad-hoc score+upsert
  - `GET /customers/{user_id}/fingerprints` (READ_ONLY+) — IP/UA history
- **`/control` UI**: new Abuse nav tab with a red pending-count badge driven
  by `/abuse/summary` (polled + SSE-refreshed); `/control/abuse` page with
  severity-color queue, score-bar visualization, signal-by-signal detail
  drawer, dismiss/ban/re-evaluate actions gated by role.
- **Tests** (`tests/test_abuse.py`, 14 tests passing): fingerprint upsert +
  no-op without IP; excessive-scans/failed-payments/many-ips signal triggers
  on synthetic data; clean user stays under threshold; upsert dedup + recurrence
  re-opens a dismissed flag; auto-resolve clears when signals drop; API list/
  summary/detail; dismiss → ban escalation promotes to user suspension; cannot
  ban self; RBAC matrix (READ_ONLY blocked from mutations, ANALYST can dismiss
  but not ban, ADMIN can ban); candidate selection picks the right users.

## Phase 6 — Support / Fix Service — DELIVERED

- **Schema (migration 0021)**: `support_tickets` (auto-incrementing `number`
  for the WH-#### display tag, FK user + assignee SET NULL, optional
  `source_scan_id` / `verification_scan_id` linking the issue scan and the
  fix-verification scan, `sla_due_at` stamped at creation from the customer's
  plan tier, `opened_at` / `first_response_at` / `resolved_at` / `closed_at`)
  + `support_ticket_events` (per-ticket timeline with `kind` =
  comment/status_change/priority_change/assignment/system and `visibility` =
  public|internal so the customer self-service portal can later hide staff-
  only entries).
- **SLA matrix** (`services/support.py`): free=7d, pro=48h, shield=24h,
  enterprise=8h. `is_breached(ticket)` is SQLite/Postgres-portable (handles
  the naive datetime that sqlite returns on reload).
- **Lifecycle service**:
  - `create_ticket` validates category + priority, stamps SLA, writes a
    system timeline entry.
  - `change_status` records the transition, flips terminal timestamps, and
    *clears* `resolved_at`/`closed_at` if a ticket is re-opened.
  - `change_priority` / `assign` write their own timeline entries.
  - `add_event(kind="comment", visibility="public")` stamps
    `first_response_at` the first time a staff member replies publicly —
    so we can measure responsiveness separately from full resolution.
  - `attach_verification_scan` links a staff-initiated rescan + records it.
- **API** (`/internal/tickets/*`, audited):
  - `GET /tickets` (READ_ONLY+) — filter status/priority/assignee/user +
    `breached_only`
  - `GET /tickets/summary` — by-status counts + open + breached (drives the
    Tickets nav badge with red on breach, amber on open)
  - `GET /tickets/{id}` — detail + full timeline + enriched emails
  - `POST /tickets` (SUPPORT+) — create
  - `POST /tickets/{id}/{status,priority,assign,comment}` (SUPPORT+)
  - `POST /tickets/{id}/verify-rescan` (SUPPORT+) — create + enqueue a new
    scan against the same website and link it as the verification scan
    (reuses `scan_jobs.create_scan_job(is_admin=True)` + best-effort Celery
    enqueue, mirroring `scan_ops.force_rescan`).
- **`/control` UI**: new Tickets nav tab with a colored badge (red if any
  ticket is SLA-breached, amber otherwise); `/control/tickets` page with
  status/priority filters + breached-only toggle, WH-#### display numbers,
  per-ticket SLA pill (`Nh late` red on breach, `Nh` amber when ≤4h, plain
  when comfortable); detail drawer with full timeline (internal vs public
  entries color-coded), status/priority selects, verify-rescan button, and
  a comment composer with a public/internal visibility selector.
- **Tests** (`tests/test_support.py`, 11 tests passing): service create
  stamps SLA from plan (Shield < Free), input validation, status/priority
  changes record timeline + flip `resolved_at`, re-opening clears terminal
  timestamps, first public comment stamps `first_response_at` (internal
  notes don't), `is_breached` only for active tickets, `search(breached_only)`
  filter; API create→full-lifecycle (status, priority, public/internal
  comments, resolve), invalid input 422, verify-rescan blocked without a
  source scan, READ_ONLY can view but not mutate.

## Phase 7 — Team Mgmt + Deploys + Infra — DELIVERED

- **Schema (migration 0022)**: `deployments` (service / sha / status / actor /
  note / started_at / finished_at) for manual deploy history;
  `infrastructure_samples` (taken_at, queue_depth, worker_alive,
  worker_heartbeat_age_s, redis_used_memory_mb, active_scans) for trend
  storage.
- **Team service** (`services/team.py`):
  - `list_staff` returns every account with a non-`none` admin role.
  - `change_admin_role` validates the role and **flips the legacy `is_admin`
    flag** in lockstep so older code paths (and the user model's existing
    `is_admin` check) stay consistent.
  - `recent_logins(hours)` reads `last_login_at` (Phase 4 wiring).
  - `force_logged_out_users` resolves every `auth:denylist:*` Redis key
    back to a user record so staff can see exactly whose sessions are
    currently revoked.
- **Deploys service** (`services/deployments.py`): `current_sha()` returns
  the Railway-injected `RAILWAY_GIT_COMMIT_SHA` — the source of truth for
  what's running. `record(...)` validates service + status + minimum sha
  length and stores a row. `list_recent(...)` for the page.
- **Infra metrics** (`services/infra_metrics.py` + `worker/infra_tasks.py`):
  `sample_infra` beat task (every 5 min) snapshots queue depth, worker
  heartbeat age + alive, Redis used memory (in MB), and active-scan count
  in a single row. `history(hours)` returns the time-series for the chart;
  `prune_older_than` keeps the table bounded.
- **Maintenance mode** (`services/maintenance.py` +
  `middleware.MaintenanceModeMiddleware`): a Redis flag
  `webhound:maintenance_mode` (+ optional reason) toggled from
  `/internal/maintenance` (SUPER_ADMIN). While engaged, the middleware
  short-circuits write paths (`/scan-jobs`, `/websites`, `/scan-schedules`)
  with `503` so staff can do infra work without losing queued scans. Reads,
  the SOC, and the auth flow stay open. Fails open if Redis is unreachable.
- **API** (`/internal/team*`, `/internal/deploys*`, `/internal/infra/history`,
  `/internal/maintenance`, audited):
  - `GET /team` + `GET /team/sessions` (READ_ONLY+) — roster, recent logins,
    revoked sessions.
  - `POST /team/{user_id}/role` (SUPER_ADMIN) — change role; cannot change
    your own; 422 on invalid role.
  - `GET /deploys` + `GET /deploys/current` (READ_ONLY+) — history + the
    live `RAILWAY_GIT_COMMIT_SHA`.
  - `POST /deploys` (ADMIN) — manual record.
  - `GET /infra/history?hours=N` (READ_ONLY+).
  - `GET /maintenance` (READ_ONLY+) + `POST /maintenance` (SUPER_ADMIN) —
    `{active: bool, reason?: string}`.
- **`/control` UI**: new **Team** and **Deploys** nav tabs.
  - `/control/team`: maintenance-mode card with engage/disengage button
    (color shifts amber while engaged); staff roster with per-row role
    selector (SUPER_ADMIN-only, self-row disabled); recent-logins table;
    revoked-sessions table when present.
  - `/control/deploys`: a card with the live commit SHA (linked to GitHub),
    service filter, history table with status colors + a **LIVE** badge on
    the row matching the running SHA, "Record deploy" dialog (ADMIN).
- **Tests** (`tests/test_team_deploys.py`, 11 tests, all passing): role
  change validates + flips `is_admin`, list_staff excludes `none`,
  recent_logins window filter, deploy validators reject bad inputs,
  record+list, `current_sha` reads the env, infra `history` returns
  rows ordered by `taken_at`, API team-roster lists only staff, role
  changes are blocked for self + non-super-admin + bad role, deploy
  record happy path + READ_ONLY blocked, maintenance toggle is
  SUPER_ADMIN-only and idempotent.

## Phase 8 — Log Explorer + Audit UI — DELIVERED

- **Schema (migration 0023)**: `logs` table (timestamp, source, severity,
  message text, JSONB context, request_id, actor_email — indexed by
  timestamp, source, severity, source+severity, request_id). The Audit
  browser reuses `admin_audit_logs` from Phase 1 — no new schema there.
- **Logs service** (`services/logs.py`): `record()` normalizes unknown
  severities to `info` and caps the message at 8000 chars so a runaway
  traceback can't blow up the table; `search_logs(...)` supports source +
  exact severity + `severity_at_least` threshold + free-text `q` ILIKE on
  message + `request_id` + time window; `logs_to_csv(...)` flattens
  newlines so each row stays on one CSV line. Same shape for
  `search_audit(...)` over `admin_audit_logs` with action/actor/target/q/
  time filters; `audit_to_csv` json-encodes the detail blob.
- **Server-error emit**: the global `internal_exception_handler` now opens
  a fresh session via the new `get_session_factory()` helper and calls
  `record_server_error(...)` — every 500 lands in the Log Explorer with
  the method, path, exception class, and request_id. Fully best-effort:
  any failure in the logger never shadows the original 500.
- **API** (4 routes, READ_ONLY+):
  - `GET /internal/logs` — paginated search with all the filters above
  - `GET /internal/logs.csv` — same filters, returns CSV (up to 10 000 rows)
  - `GET /internal/audit` — paginated audit search
  - `GET /internal/audit.csv` — audit CSV export
- **`/control` UI**: new Logs nav tab; `/control/logs` page with two tabs
  — **Application logs** (free-text search box, source select, exact
  severity or threshold, severity-colored pill, expandable JSON context
  per row, CSV export button) and **Audit trail** (free-text q + exact
  action + actor email filters, action-colored chip, expandable detail
  blob, CSV export). CSV download goes through `fetch + Authorization`
  so it inherits the same Bearer auth the API uses.
- **Tests** (`tests/test_logs.py`, 9 tests, all passing): unknown severity
  → info; message clipped at 8000 chars; severity-threshold filter; combined
  source/q/request_id filter; CSV header + newline flattening + exact row
  count; audit action/target_id/q filters; API logs search + threshold;
  CSV content-type + body; audit search + CSV; **customer accounts get 403
  on all four routes**.

## Phase 9A — Threat Intelligence — DELIVERED

A scoped slice of the broader Phase 9 expansion (full multi-tenant org_id
scoping is deferred — it touches every model + ACL and is genuinely
risky against live paying customers; the user keeps explicit control of
that one). Threat intel is additive and wires straight into Phase 5.

- **Schema (migration 0024)**: `threat_indicators` (kind ip/domain/url/
  hash/cve, value, source, severity, confidence 0–100, JSONB tags, notes,
  first/last_seen, optional `expires_at` TTL). Deduped on
  `(kind, value, source)`.
- **Service** (`services/threat_intel.py`):
  - `upsert_indicator` validates kind + severity, clamps confidence to
    0–100, **normalizes the value** (lowercases domains/URLs/hashes, strips
    trailing dots) so dedup actually dedups across casing/whitespace.
  - `match(kind, value)` — fast lookup, excludes expired rows; returns
    every matching indicator across feeds.
  - `import_feed(source, rows, default_severity, default_confidence,
    expires_in_days)` — bulk upsert with per-row override, skips bad rows.
  - `expire_stale()` — prunes everything past its TTL.
- **Fraud integration** — `services/fraud._signal_threat_intel_ip` runs
  the user's distinct login IPs (last 7d) through `ti_svc.match` and
  adds the new **`threat_intel_ip`** reason (weight 35 — the heaviest
  single signal). A login from a known-bad IP plus any other signal now
  flags hard.
- **API** (`/internal/threat-intel/*`, audited):
  - `GET /indicators` (READ_ONLY+) — filter kind/source/severity/q +
    paginated, hides expired by default
  - `GET /indicators/match?kind=&value=` (READ_ONLY+) — probe
  - `POST /indicators` (ANALYST+) — manual add (audit logs whether it
    was a new row or an update)
  - `DELETE /indicators/{id}` (ADMIN) — explicit deletion
  - `POST /import` (ADMIN) — bulk feed import; audit detail records
    counts
- **`/control` UI**: new Threat Intel nav tab; `/control/threat-intel`
  page with a **Match Probe** card (severity-colored hits with source +
  confidence + notes), filter row (search, kind, severity, "show
  expired" toggle), indicator table with delete buttons (ADMIN), Add
  dialog (ANALYST), and Bulk Import dialog (ADMIN — paste one indicator
  per line + pick default kind/severity, shows created/updated/skipped
  counts when done).
- **Tests** (`tests/test_threat_intel.py`, 8 tests, all passing): kind/
  severity validation; value normalization dedups domain casing +
  trailing dot; confidence clamps to 0–100; `match` excludes expired
  rows; `import_feed` returns created/updated/skipped exactly; `expire_stale`
  deletes only rows past their TTL; **the fraud evaluator's new IP
  signal triggers when a known-bad IP appears in a user's fingerprints
  and the resulting score alone clears the flag threshold**; API
  full-lifecycle (add → list → match → import → delete) + RBAC matrix
  (READ_ONLY blocked from mutations, ANALYST can add not delete/import,
  ADMIN can do everything).

## Phase 10 — SOC operational uplift — DELIVERED

A platform-wide refinement pass: telemetry contracts, engine state machine
+ maintenance registry, full SOC incident management (correlation, status
workflow, MTTR, SLA), and a polished Command Center.

- **Telemetry contracts** (`apps/api/telemetry.py`): single source of truth
  shared by every module — `OperationalStatus`, `Severity` (+ rank/compare),
  `EventKind` (stable codes: `scan.*`, `alert.*`, `incident.*`, `auth.*`,
  `customer.*`, `billing.*`, `infra.*`, `engine.*`, `abuse.*`, `ticket.*`,
  `deploy.*`, `admin.action`), and `Event` envelope with a best-effort
  `publish_event()` that fans onto the existing Redis pub/sub channel the
  layout's SSE listener already subscribes to. Backward-compatible — Phase 3
  alert publishes ride the same channel and still work.
- **Schema (migration 0025)**:
  - `engines` — per-engine registry: `maintenance_mode`, `auto_disable_at_failure_pct`,
    `auto_disabled_at`, notes, updated_by_email. Opt-in metadata (engines
    without a row use safe defaults).
  - `incidents` — INC-#### display number, `correlation_key`, source, title,
    severity, status (open / acknowledged / investigating / mitigated /
    resolved / suppressed), target pointers, JSONB detail, `alert_count`
    counter, first/last_seen, `sla_due_at`, assignee FK, ack/mitigate/resolve
    timestamps + actor emails, **MTTR seconds** stamped at resolution.
  - `incident_events` — per-incident timeline (alert_attached, status_change,
    note, system) with `alert_id` for deep-linking.
- **Engine state machine** (`services/engines.py`): `compute_state(runs,
  failed, maintenance)` → `healthy / degraded / unstable / critical /
  maintenance` (thresholds 15/40/70%, sub-3-run floor). `health_scorecards()`
  joins the 7-day diagnostic window to the registry and ranks critical
  first. The existing `GET /internal/engines` now returns the richer shape
  additively (state, maintenance_mode, auto_disable_at_failure_pct, max_ms,
  notes); Phase 2 fields are preserved exactly so older clients keep working.
- **Engine registry API** (`/internal/engines/{name}/*`, audited):
  - `POST /maintenance` (ANALYST+) — toggle the maintenance flag + publish
    `engine.maintenance` event.
  - `POST /threshold` (ADMIN) — set or clear the auto-disable failure
    percentage (clamped 0–100).
- **Incident management** (`services/incidents.py`):
  - `correlate_alert(alert)` — find an open incident whose correlation key
    `<source>:<target_type>:<target_id>` (or `dedup_key`/`source` fallback)
    matches, bump it, escalate severity if the new alert is higher, or open
    a new INC-#### with a per-severity SLA (critical 1h / high 4h / medium
    24h / low 72h / info 7d).
  - Lifecycle: `change_status` validates the transition, stamps the right
    metadata, **computes MTTR at resolve**, clears terminals on re-open.
  - `summary()` powers the nav badge + Command Center banner (active counts
    by severity + breach count + the single highest-severity active incident).
  - **Wired into the alert service**: `upsert_alert` now calls
    `_correlate_into_incident` after the alert is flushed. Wrapped in
    try/except so correlation can never break alert creation. SQLite-portable
    (handles the naive datetime SQLite returns on reload for the MTTR sub).
- **Incidents API** (`/internal/incidents*`, audited): list with status /
  severity / source / breached-only filters (READ_ONLY+), summary, detail
  with full timeline, status changes (ANALYST+), assignment (ADMIN), note
  composer (ANALYST+).
- **Command Center polish** (`/internal/command-center`):
  - Infra block now returns `overall: operational | degraded | maintenance
    | offline` derived from db/redis/worker/maintenance signals. The header
    pill replaces the old "offline" text with semantic labels.
  - `incidents` block returns the same shape as `/internal/incidents/summary`
    so the dashboard can render the active-incident banner with one fetch.
- **`/control` UI**: new Incidents nav tab (badge = active count, turns red
  on SLA breach); the "Reconnecting / SOC Online" header pill replaces the
  binary `offline` text; the Posture pill (Operational / Degraded /
  Maintenance / Offline) sits alongside the existing infra grid; a top-of-
  page incident banner appears when there's an active critical/high. The
  Engines page shows a state pill per card, a per-state count strip, and
  role-gated **Maintenance** + **Threshold** buttons.
- **Tests** (`tests/test_incidents.py`, 11 tests, all passing): engine state
  thresholds + maintenance trumping + registry get_or_create idempotency +
  threshold clamping; **alert upsert opens an incident then attaches the
  second occurrence** (the headline integration); severity escalation
  records a system event + bumps the incident; full status lifecycle stamps
  ack/mitigated/resolved timestamps and **computes MTTR**; re-open clears
  terminals; summary picks the top incident by severity; API list/summary/
  detail/status with 422 on bad status; READ_ONLY blocked from mutations
  but can still read.

Total suite: **204 tests across Phases 1–10, zero regressions**.

## Roadmap — what's still next

The user's Phase-10 priority list called out improvements beyond what's in
this increment — these are the obvious next slices (each a clean, additive
commit that won't touch live customer data unsafely):

- **Live Event Stream UI** — drop the typed `Event` envelope from
  `apps/api/telemetry.py` into a `/control/events` feed (the SSE channel
  already carries them; the consumer just needs to render the typed shape).
- **Engine reliability trend history + auto-disable enforcement** — the
  evaluator already has the threshold value; wire it to flip
  `maintenance_mode=True` + open a `engine.degraded` incident when crossed.
- **sensitive_paths deep-dive** — diagnostic endpoint that returns the last
  N runs of one engine with timeout markers + crawl depth + retry intelligence.
- **Infrastructure Operations page** — dedicated `/control/infra` rendering
  the 24h time-series we already capture in `infrastructure_samples`.
- **Threat-intel auto-feeds** — scheduled importer for public IP/domain
  feeds (a worker beat task; trivial on the Phase 9A foundation).
- **Multi-tenant / MSSP org_id** — still explicitly deferred (touches every
  customer-scoped model + ACL; needs an explicit go-ahead + migration plan).

## Phase 9 remaining

- **Multi-tenant / MSSP** — org_id on every customer-scoped model + ACL
  rewrite. Deferred: lands on live paying customers; needs an explicit
  green light + migration plan + dry run.
- **SIEM / endpoint integrations** — outbound webhook + Splunk HEC
  shape; sits cleanly on top of the new `logs` + `admin_audit_logs`
  surfaces.
- **Multi-region** — Railway-side infra change rather than app schema.

**Phase 9 — Future expansion** (area 18)
- Multi-tenant/MSSP (org_id scoping), AI copilots, automated remediation, threat-
  intel feeds, SIEM/endpoint integrations, multi-region.

### Planned schema (beyond Phase 1's `users.admin_role` + `admin_audit_logs`)
`engines`, `alerts`, `incidents`, `alert_comments`, `notifications`, `tickets`,
`ticket_events`, `abuse_flags`, `ip_device_fingerprints`, `deployments`,
`infrastructure_metrics`, `logs`, `internal_notes`. (`scans`, `findings`,
`subscriptions`, `users` already exist.)

---

## Security notes
- API-side RBAC on every `/internal/*` route is the boundary; the UI gate is UX.
- `/control` + `/admin` are disallowed in `robots.txt`.
- All privileged mutations must `record_action()` to the audit trail.
- Ban/force-logout (Phase 4) needs a Redis JWT-denylist since tokens are stateless.
- MFA-ready: the model can carry an MFA flag; enforce in `get_current_user` later.
- Consider splitting `/control` to its own deployment so the internal JS bundle is
  never served to customers.
