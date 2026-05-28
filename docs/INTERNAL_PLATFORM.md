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

## Roadmap — feature areas 8–18 (phased)

Each phase adds models + `/internal/*` routes + a `/control` page, reusing the
RBAC + audit foundation.

**Phase 7 — Team Mgmt + Deploys + Infra** (areas 8, 10)
- Tables: `deployments`, `infrastructure_metrics`. Role management UI, session
  monitoring (Redis-backed sessions), deploy/rollback history, container/queue
  metrics, restart-service/maintenance-mode controls (Railway API).

**Phase 8 — Live Log Explorer + full Audit UI** (areas 11, 12)
- Tables: `logs` (structured, JSONB, indexed by source/severity/time). Splunk-style
  full-text search, query builder, severity/time filters, saved searches, export.
- Full audit-trail browser over `admin_audit_logs`.

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
