# WebHound — Production Launch Readiness

_Last hardening pass: 2026-05-26. Covers API (FastAPI), worker (Celery), scanner,
frontend (Next.js), Postgres, Redis, and live Stripe billing on Railway + Vercel._

---

## 1. Launch-readiness summary

| Area | Status | Notes |
|---|---|---|
| Auth & sessions | ✅ | bcrypt, email-OTP login, per-email lockout, no IDOR |
| Billing (Stripe) | ✅ LIVE | verified end-to-end (checkout → webhook → DB sync at $0) |
| Scanner pipeline | ✅ | 9/9 prod scans completed; 1,546 tests green; SSRF-guarded |
| Worker + scheduling | ✅ | Celery beat dispatching every minute; daily monitoring live |
| Secrets / Stripe key hygiene | ✅ | no keys in repo; env-only; prod startup validation added |
| Error monitoring (Sentry) | ⚙️ wired | code shipped; **set `SENTRY_DSN` / `NEXT_PUBLIC_SENTRY_DSN` to activate** |
| Observability | ✅ | request IDs, `/health/ready`, health probes |
| SEO | ✅ | robots, sitemap, canonical, structured data |
| DB backups | ⚠️ verify | confirm Railway PITR/backups enabled (§3) |

**Verdict:** see §11.

---

## 2. Exact production environment variables

### API service (Railway: `webhound`)
| Var | Required | Notes |
|---|---|---|
| `DATABASE_URL` | ✅ | Postgres; `postgresql://` is normalized to `+asyncpg` |
| `REDIS_URL` | ✅ | rate limiting, auth lockout, Celery broker/result |
| `SECRET_KEY` | ✅ | 64-hex; **must not** be the default (startup rejects it in prod) |
| `APP_ENV` | ✅ | `production` (gates all prod validations) |
| `DEBUG` | ✅ | `false` |
| `FRONTEND_URL` | ✅ | `https://webhoundsecurity.com` (Stripe redirect base) |
| `API_BASE_URL` | ✅ | `https://api.webhoundsecurity.com` (OAuth redirect base) |
| `CORS_ORIGINS` | ✅ | JSON array or comma list of allowed origins |
| `STRIPE_SECRET_KEY` | ✅ | live key; **startup fails in prod if missing** |
| `STRIPE_WEBHOOK_SECRET` | ✅ | live endpoint signing secret; startup-validated |
| `STRIPE_PRICE_PRO_MONTHLY` | ✅ | live price id; startup-validated |
| `STRIPE_PRICE_SHIELD_MONTHLY` | ✅ | live price id; startup-validated |
| `STRIPE_PRICE_ENTERPRISE_MONTHLY` | ✅ | live price id; startup-validated |
| `RESEND_API_KEY` | ✅ (or SMTP_*) | email delivery (verification, reset, alerts) |
| `RESEND_FROM_EMAIL` / `RESEND_FROM_NAME` | ✅ | sender identity |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | optional | Google OAuth |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | optional | GitHub OAuth |
| `SENTRY_DSN` | recommended | **enables error monitoring** (off if unset) |
| `SENTRY_TRACES_SAMPLE_RATE` | optional | `0` = errors only; e.g. `0.1` for perf tracing |
| `ADMIN_EMAILS` | optional | auto-promote to admin (JSON/CSV) |
| `ADMIN_QUOTA_BYPASS` | must be unset/0 | only `1` bypasses quotas for admins |
| `DEV_ALLOW_UNVERIFIED_SCANS` / `DEV_SKIP_DOMAIN_VERIFICATION` | must be unset | startup rejects these in prod (SSRF safety) |

### Worker service (Railway: `worker`)
Same DB/Redis/Stripe/email vars as API, plus `APP_ENV=production`, and
`SENTRY_DSN` + `SENTRY_TRACES_SAMPLE_RATE` to enable worker error capture.

### Frontend (Vercel)
| Var | Required | Notes |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | ✅ | `https://api.webhoundsecurity.com` |
| `NEXT_PUBLIC_SITE_URL` | ✅ | `https://webhoundsecurity.com` (canonical/SEO) |
| `NEXT_PUBLIC_SENTRY_DSN` | recommended | enables browser + server error capture (off if unset) |

> Sentry is **environment-aware**: it does nothing unless the DSN is set **and**
> the environment is production. Safe to deploy the code before setting DSNs.

---

## 3. Database backup, restore & migration safety

**Backups (Railway Postgres) — VERIFY before launch:**
- Confirm the Postgres plugin has **automated daily backups / PITR** enabled
  (Railway dashboard → Postgres service → Backups). This is the one item the
  code can't enforce.
- Recommended: **daily automated backups, ≥7-day retention**; take a **manual
  snapshot immediately before any migration deploy**.

**Manual backup / restore (anytime):**
```bash
# dump (uses the public proxy URL; never commit the dump)
railway run --service <postgres> -- bash -c 'pg_dump "$DATABASE_PUBLIC_URL" -Fc -f /tmp/wh.dump'
# restore into a fresh DB
pg_restore --clean --no-owner -d "$TARGET_DATABASE_URL" wh.dump
```

**Migrations (Alembic) — current revision: `0016`.**
- Pre-deploy: review the migration, **take a manual snapshot**, and verify it
  applies on a copy. Check live revision: `GET /health/version` → `schema_revision`.
- Migrations run on deploy. **Rollback safety:** prefer additive/backward-
  compatible migrations (add columns nullable, backfill, then enforce in a later
  release) so an app rollback doesn't break against the new schema.
- Emergency downgrade: `alembic downgrade -1` — **only if the migration is
  reversible and you've snapshotted first.** Several data migrations are not
  cleanly reversible; restoring the pre-migration snapshot is the safer path.

---

## 4. Operational health audit (verified)

| Concern | Finding | Status |
|---|---|---|
| Celery beat scheduling | `dispatch_scheduled_scans` every minute, `heartbeat` every 5 min; observed firing in prod | ✅ |
| Worker retries | `run_scan` `max_retries=3`, 60s backoff; `task_acks_late=True` re-queues on worker death | ✅ |
| Webhook reliability | sig-verified; handler returns 200 even on internal error (no Stripe retry storm); `/billing/sync` + admin `/billing/admin/resync` as fallbacks | ✅ |
| Scan cancellation | `/scan-jobs/{id}/cancel` transitions QUEUED/RUNNING→CANCELLED via a guarded state machine | ✅ (soft — see risks) |
| Redis connectivity | broker + rate-limit + auth-lockout all on Redis | ✅ working; ⚠️ hard dep (see risks) |
| API request timeouts | scanner httpx: connect 10s, read = `request_timeout_seconds`, pool 5s; per-request bounded | ✅ |
| Email delivery | Resend (primary). `_send_email` uses Resend **or** SMTP — **no auto-failover** | ⚠️ see risks |
| Graceful failure | scan engine errors mark job FAILED with message; 500s return generic body (no leak) | ✅ |
| Stale jobs | `acks_late` re-queues crashed tasks; **no dedicated reaper / Celery `time_limit`** | ⚠️ see risks |

---

## 5. Security re-audit (post-hardening)

✅ **Solid:** prod config hardened (APP_ENV/DEBUG/SECRET_KEY/dev-flags validated at
startup); **SSRF** egress guard with **DNS-rebinding IP pinning** (validates +
pins the resolved public IP per hop; TLS SNI preserved); domain-ownership
verification enforced before scans; **rate limiting** keyed on real client IP;
**auth lockout** (5 fails/15 min per email); **CORS** explicit allowlist (no `*`);
**CSP** with `base-uri`/`object-src 'none'`/`frame-ancestors 'none'`; **IDOR**
prevention (all multi-tenant queries scoped by owner); **no payment data logged**;
500 handler returns generic body + reports to Sentry with secrets scrubbed.

⚠️ **Accepted/known (see §6):** CSP keeps `script-src`/`style-src 'unsafe-inline'`
(inline style attributes; nonce migration deferred); in-memory rate limiter
(per-instance); SSRF DNS-rebinding TOCTOU residual is mitigated by IP pinning but
not 100% eliminated for exotic resolvers.

---

## 6. Remaining risks (ranked)

| # | Sev | Risk | Recommendation |
|---|---|---|---|
| 1 | **MED** | **Redis is a hard dependency for auth** — if Redis is down, lockout/rate-limit calls raise and login degrades. | Confirm Redis HA on Railway; consider wrapping rate-limit calls to fail-open on Redis error (availability) post-launch. |
| 2 | **MED** | **No email failover** — a Resend outage breaks verification/reset/alert emails (errors now surface to Sentry). | Add Resend→SMTP fallback, or alert on email send failures (§8). |
| 3 | **MED** | **No stale-job reaper / Celery `time_limit`** — a hung scan can occupy a worker slot. | Add `task_time_limit`/`task_soft_time_limit` to Celery and a periodic reaper for jobs stuck RUNNING > N min. |
| 4 | LOW | **Soft cancellation** — cancel marks DB CANCELLED but doesn't `revoke` the in-flight Celery task. | Add `celery revoke(terminate=True)` on cancel, and have the worker check job status before persisting results. |
| 5 | LOW | **In-memory rate limiter** — per-instance counts; resets on redeploy. | Move to Redis-backed counters when scaling API > 1 instance. |
| 6 | LOW | **Restricted Stripe key** — works, but a scope change could break billing. | Prefer a full `sk_live`, or document the exact restricted scopes. |
| 7 | LOW | **CSP `unsafe-inline`/`unsafe-eval`** | Nonce migration (needs middleware + Report-Only rollout); inline style attrs block full removal. |
| 8 | INFO | No staging env; changes deploy straight to prod. | Add a staging environment for migration/UI verification. |

**Untested (out of scope this pass):** load/stress testing, formal pentest, legal
review of Terms/Privacy/AUP, accessibility audit.

---

## 7. Recommended monitoring dashboards
- **API health:** request rate, p50/p95 latency, 4xx/5xx rate, `/health/ready` status.
- **Worker:** task throughput, failure rate, retry count, **queue depth** (Redis `LLEN` on the Celery queue), beat liveness (heartbeat task).
- **Scans:** scans started/completed/failed, **scan duration** (created→completed), failure reasons.
- **Billing:** checkout sessions, active subscriptions, webhook delivery success (Stripe dashboard → Webhooks), failed payments.
- **Infra:** Postgres connections/CPU/disk, Redis memory/connections.
- **Sentry:** error volume by environment/release, slowest transactions (if tracing enabled).

## 8. Recommended alerts
- API 5xx rate > 1% (5 min) → page.
- `/health/ready` returns 503 → page (DB or Redis down).
- Celery queue depth > N for > 5 min, or **beat heartbeat missing > 10 min** → page.
- Scan failure rate > 20% (15 min) → investigate.
- **Email send failure** (Sentry event from `_send_email`) → investigate (risk #2).
- Stripe webhook delivery failures (Stripe dashboard alert) → investigate.
- New Sentry issue in `production` → notify.

---

## 9. Rollback procedure
1. **App (API/worker/frontend):** Railway → service → Deployments → **Redeploy**
   the previous known-good deployment (or Vercel → Promote previous). Env vars are
   applied on redeploy.
2. **Bad env change:** restore the previous value in Railway/Vercel Variables →
   redeploy. (A missing required Stripe/secret var fails the new deploy's
   healthcheck, so Railway keeps the prior container — no outage.)
3. **Bad migration:** restore the pre-migration **DB snapshot** (§3), then redeploy
   the matching app version. Only use `alembic downgrade` if the migration is
   reversible.
4. **Compromised Stripe key:** roll it in Stripe → set new `STRIPE_SECRET_KEY` in
   Railway → redeploy → verify with a $0 coupon checkout.

## 10. Incident-response checklist
1. **Detect** — Sentry/alert/report. Note time + `X-Request-ID` if available.
2. **Assess blast radius** — auth? billing? scanning? data exposure?
3. **Contain** — disable the affected path if needed; roll keys if credentials are involved; scale down/pause workers if scans are the issue.
4. **Communicate** — status note to affected users if data/billing is impacted.
5. **Fix** — patch or roll back (§9).
6. **Verify** — `/health/ready` 200, a real scan completes, a $0 checkout syncs.
7. **Post-mortem** — root cause, prevention, add a regression test/alert.

**Quick triage commands:**
```bash
curl -s https://api.webhoundsecurity.com/health/ready          # DB + Redis
curl -s https://api.webhoundsecurity.com/health/version        # commit + schema rev
railway logs --service <api|worker>                            # recent logs
```

---

## 11. Final verdict

**SAFE TO LAUNCH — conditional on:**
1. Set **`SENTRY_DSN`** (API + worker) and **`NEXT_PUBLIC_SENTRY_DSN`** (Vercel) so
   you have eyes on production errors from minute one. _(Code is shipped and inert
   until set.)_
2. **Confirm Railway Postgres backups/PITR** are enabled (§3).
3. **Roll** any Stripe key that was ever exposed; confirm only a fresh key is live.

Everything functional is verified working in production (auth, live billing,
scanning, scheduled monitoring) and the security posture is strong. The ranked
risks in §6 are operational resilience items appropriate to address shortly after
launch, not launch blockers. With the three conditions above met, **ship it.**
