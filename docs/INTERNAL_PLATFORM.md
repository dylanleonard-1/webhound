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

## Roadmap — feature areas 5–18 (phased)

Each phase adds models + `/internal/*` routes + a `/control` page, reusing the
RBAC + audit foundation.

**Phase 4 — Customer + Billing Ops** (areas 5, 9)
- APIs: customer search; ban/suspend/force-logout (JWT denylist in Redis); reset
  MFA; billing/scan/login/support history; internal notes (`internal_notes`).
- Billing ops: true MRR/ARR/churn/refunds/trial-conversion from Stripe + local;
  webhook delivery monitoring.

**Phase 5 — Fraud & Abuse** (area 6)
- Tables: `abuse_flags`, `ip_device_fingerprints`. Abuse scoring (excessive scans,
  bot/VPN/proxy, failed-payment abuse, API abuse, credential stuffing), auto-ban
  rules, manual review queue.

**Phase 6 — Support / Fix Service** (area 7)
- Tables: `tickets`, `ticket_events`, `ticket_attachments`. SLA tracking, assign
  technicians, link scans, before/after rescan comparison, verification rescans.

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
