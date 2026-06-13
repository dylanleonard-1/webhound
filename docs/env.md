# Environment variable reference

Single source of truth for every environment variable WebHound reads at
runtime. Generated from an audit of `os.getenv` / `os.environ` (Python),
`process.env` (Next.js), `apps/api/config.py` (pydantic `Settings`), and the
`docker-compose*.yml` / `railway.toml` deploy configs.

Templates:

- Backend + worker + scanner: [`.env.example`](../.env.example) (repo root, shared `.env`)
- Frontend: [`apps/web/.env.example`](../apps/web/.env.example) (Vercel / `.env.local`)

Startup validation lives in `apps/api/config.py` (API) and
`worker/celery_app.py` (worker). Run `python scripts/audit_runtime_config.py`
for a safe, no-secrets snapshot of what is actually configured.

Columns: **Secret** = must never be committed/logged. **Prod-req** = production
startup fails without it. **Default** = value used when unset.

## Core

| Var | Used in | Prod-req | Secret | Default | Failure if missing/wrong |
|-----|---------|:-:|:-:|---------|--------------------------|
| `APP_ENV` | api, worker | – | – | `development` | Invalid value → API startup fails (`development\|staging\|production`) |
| `DEBUG` | api | – | – | `false` | – |
| `LOG_LEVEL` | api | – | – | `INFO` | – |
| `DATABASE_URL` | api, worker, migrations, scripts | ✓ | ✓ | `postgresql+asyncpg://webhound:webhound@localhost:5432/webhound` | API/worker cannot reach DB; prod must override the default |
| `REDIS_URL` | api, worker | ✓ | – | `redis://localhost:6379/0` | Celery + rate limiting disabled / broken |
| `SECRET_KEY` | api | ✓ | ✓ | `dev-secret-key-change-in-production` | **Prod startup fails** if left at insecure default |
| `ALGORITHM` | api | – | – | `HS256` | – |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | api | – | – | `1440` | – |
| `API_BASE_URL` | api | ✓ | – | `http://localhost:8000` | Wrong OAuth redirect URIs |
| `FRONTEND_URL` | api | ✓ | – | `http://localhost:3000` | Wrong post-auth redirects / email links |

## Security / CORS

| Var | Used in | Prod-req | Secret | Default | Failure if missing/wrong |
|-----|---------|:-:|:-:|---------|--------------------------|
| `CORS_ORIGINS` | api | ✓ | – | localhost list | Browser requests from prod domains blocked |
| `CORS_ALLOW_CREDENTIALS` | api | – | – | `true` | – |
| `CORS_ORIGIN_REGEX` | api | – | – | Vercel preview regex | **Prod startup fails** if not a compilable regex |
| `RATE_LIMIT_ENABLED` | api | – | – | `true` | – |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | api | – | – | `100` | – |
| `ADMIN_VERIFY_BYPASS` | api (`routers/websites.py`) | – | – | `0` (off) | See **Admin bypass** below |
| `ADMIN_QUOTA_BYPASS` | api (`billing/quota.py`) | – | – | `0` (off) | See **Admin bypass** below |
| `ADMIN_BYPASS_ALLOW_IN_PROD` | api | – | – | `0` (off) | Required override to use bypass flags in production |
| `DEV_ALLOW_UNVERIFIED_SCANS` | api | – | – | `false` | **Prod startup fails** if `true` |
| `DEV_SKIP_DOMAIN_VERIFICATION` | api | – | – | `false` | **Prod startup fails** if `true` (SSRF risk) |
| `ADMIN_EMAILS` | api | – | – | (built-in) | Emails auto-promoted to admin on signup |

### Admin bypass flags (DANGEROUS)

`ADMIN_VERIFY_BYPASS` and `ADMIN_QUOTA_BYPASS` let a **verified admin** user skip
domain-ownership verification or scan quotas respectively. They exist only for
internal QA of the real flows.

- Default **off**. Ignored entirely for non-admin users.
- In production they are **refused** unless `ADMIN_BYPASS_ALLOW_IN_PROD=1` is
  also set (explicit override).
- Every use emits an audit-log entry.
- Never enable on a customer-facing deployment — verify + quota are SSRF/abuse
  controls.

## AI summaries (feature-flag)

| Var | Used in | Prod-req | Secret | Default | Failure if missing/wrong |
|-----|---------|:-:|:-:|---------|--------------------------|
| `WEBHOUND_AI_ENABLED` | api (`services/ai_summary.py`) | – | – | `0` (off → templates) | – |
| `ANTHROPIC_API_KEY` | api | – | ✓ | – | If `WEBHOUND_AI_ENABLED=1` and key missing → **API startup fails** |

## Threat intelligence (feature-flag)

| Var | Used in | Prod-req | Secret | Default | Failure if missing/wrong |
|-----|---------|:-:|:-:|---------|--------------------------|
| `VIRUSTOTAL_API_KEY` | scanner orchestrator + client | – | ✓ | – | Absent → VirusTotal provider disabled (silent) |
| `ENABLE_URLHAUS` | scanner orchestrator | – | – | `0` (off) | – |
| `URLHAUS_API_KEY` | scanner urlhaus client | – | ✓ (optional) | – | Optional; raises rate limits |

## Email delivery

| Var | Used in | Prod-req | Secret | Default | Failure if missing/wrong |
|-----|---------|:-:|:-:|---------|--------------------------|
| `RESEND_API_KEY` | api | – | ✓ | – | Empty → Resend disabled |
| `RESEND_FROM_EMAIL` | api | – | – | `auth@webhoundsecurity.com` | – |
| `RESEND_FROM_NAME` | api | – | – | `WebHound` | – |
| `SMTP_FALLBACK_ENABLED` | api | – | – | `0` | Enables Resend→SMTP failover |
| `SMTP_HOST` | api | – | – | – | Empty → SMTP disabled |
| `SMTP_PORT` | api | – | – | `587` | – |
| `SMTP_USERNAME` | api | – | – | – | – |
| `SMTP_PASSWORD` | api | – | ✓ | – | – |
| `SMTP_FROM_EMAIL` | api | – | – | `noreply@webhoundsecurity.com` | – |
| `SMTP_FROM_NAME` | api | – | – | `WebHound` | – |
| `SMTP_USE_TLS` | api | – | – | `true` | – |

In dev with neither provider configured, verification links/OTP are logged to
the console.

## Twilio SMS (optional)

| Var | Used in | Secret | Default | Notes |
|-----|---------|:-:|---------|-------|
| `TWILIO_ACCOUNT_SID` | api | ✓ | – | Blank → OTP logged to console (dev) |
| `TWILIO_AUTH_TOKEN` | api | ✓ | – | |
| `TWILIO_FROM_NUMBER` | api | – | – | E.164 format |

## Stripe billing

| Var | Used in | Prod-req | Secret | Notes |
|-----|---------|:-:|:-:|-------|
| `STRIPE_SECRET_KEY` | api | ✓ | ✓ | **Prod startup fails** if missing |
| `STRIPE_PUBLISHABLE_KEY` | api | – | – | Frontend reads `NEXT_PUBLIC` variant |
| `STRIPE_WEBHOOK_SECRET` | api | ✓ | ✓ | **Prod startup fails** if missing |
| `STRIPE_PRICE_PRO_MONTHLY` | api (`config.py`) | ✓ | – | **Prod startup fails** if missing |
| `STRIPE_PRICE_SHIELD_MONTHLY` | api | ✓ | – | **Prod startup fails** if missing |
| `STRIPE_PRICE_ENTERPRISE_MONTHLY` | api | ✓ | – | **Prod startup fails** if missing |

## OAuth providers

| Var | Used in | Secret | Notes |
|-----|---------|:-:|-------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | api | secret on the secret | Empty → Google login disabled |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | api | secret on the secret | Empty → GitHub login disabled |

> **Apple Sign In is not implemented.** The `APPLE_CLIENT_ID` / `APPLE_TEAM_ID` /
> `APPLE_KEY_ID` / `APPLE_PRIVATE_KEY` vars previously present in
> `.env.example` and `docker-compose*.yml` were dead config and have been
> removed. Re-add them here and wire the provider in `apps/api` before
> documenting them as active.

## Scanner tuning (`WEBHOUND_*`)

| Var | Used in | Default | Notes |
|-----|---------|---------|-------|
| `WEBHOUND_LOG_LEVEL` | scanner logger | `INFO` | |
| `WEBHOUND_DEFAULT_ENGINE_TIMEOUT` | scanner orchestrator | `60` | Per-engine seconds |
| `WEBHOUND_ENGINE_TIMEOUT_<NAME>` | scanner orchestrator | – | Per-engine override |
| `WEBHOUND_BROWSER_ENABLED` | scanner playwright runner | `0` | Headless browser discovery pass |
| `WEBHOUND_ASM_ALLOW_NETWORK` | scanner orchestrator | `1` | Attack-surface map network access |
| `WEBHOUND_THREAT_FEED_DIR` | scanner orchestrator | – | Local threat-feed directory |
| `WEBHOUND_GUEST_RETENTION_HOURS` | worker guest cleanup | `24` | |

## Worker / Celery reliability

| Var | Used in | Default | Notes |
|-----|---------|---------|-------|
| `WORKER_CONCURRENCY` | worker | `2` | |
| `SCAN_SOFT_TIME_LIMIT` | worker | `600` | Soft Celery limit (raises exception) |
| `SCAN_HARD_TIME_LIMIT` | worker | `720` | Hard Celery limit (kills task) |
| `SCAN_STALE_QUEUED_SECONDS` | worker reaper | `900` | Queued-too-long threshold |
| `SCAN_STALE_RUNNING_SECONDS` | worker reaper | `1800` | Running-too-long threshold |

## Notifications (feature-flag)

| Var | Used in | Default | Notes |
|-----|---------|---------|-------|
| `NOTIFICATIONS_ENABLED` | api, worker | `0` | Master switch for outbound alert delivery |

## Observability (optional)

| Var | Used in | Default | Notes |
|-----|---------|---------|-------|
| `SENTRY_DSN` | api, worker | – | Empty disables Sentry |
| `SENTRY_TRACES_SAMPLE_RATE` | api, worker | `0.0` | |
| `RAILWAY_GIT_COMMIT_SHA` / `GIT_COMMIT_SHA` | api health | (Railway) | Surfaced on `/health` |

## Frontend (`apps/web`, browser-exposed)

| Var | Used in | Default | Notes |
|-----|---------|---------|-------|
| `NEXT_PUBLIC_API_URL` | web | `http://localhost:8000` | Backend base URL |
| `NEXT_PUBLIC_SITE_URL` | web | `http://localhost:3000` | Canonical URL (SEO/OG/sitemap) |
| `NEXT_PUBLIC_SENTRY_DSN` | web | – | Browser error reporting |
| `SNAP_BASE_URL` / `SNAP_OUT_DIR` / `SNAP_REDUCED_MOTION` | web scripts | – | Screenshot tooling only |

## AI Knowledge Layer — MCP tooling (NOT app config)

These keys are consumed **only** by local Claude Code MCP servers used to build the
AI knowledge/evidence layer (see [`docs/ai/`](ai/README.md)). They are **not** read
by `apps/api`, `worker`, or the scanner, and `apps/api/config.py` does not define
them — leaving them blank has **zero** effect on WebHound runtime. Phase 1
**documents** these MCPs; it does **not** install or connect any MCP server.

| Var | Used in | Secret | Default | Notes |
|-----|---------|:-:|---------|-------|
| `GITHUB_TOKEN` | Claude Code GitHub MCP (local) | ✓ | – | **NEW, read-only fine-grained PAT.** Distinct from `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` (OAuth login). Blank = MCP disabled. |
| `FIRECRAWL_API_KEY` | Claude Code Firecrawl MCP (local) | ✓ | – | Doc-crawl MCP. Blank = MCP disabled. |
| `PERPLEXITY_API_KEY` | Claude Code Perplexity MCP (local) | ✓ | – | Research MCP. Blank = MCP disabled. |
| `OTX_API_KEY` *(Phase 5)* | future TI ingestion | ✓ | – | AlienVault OTX — **client not built yet**; documented for Phase 5. |
| `ABUSEIPDB_API_KEY` *(Phase 5)* | future TI ingestion | ✓ | – | AbuseIPDB — normalizer exists, **fetch client not built yet** (Phase 5). |
| `THREATFOX_AUTH` *(Phase 5)* | future TI ingestion | ✓ | – | ThreatFox — **TOS/auth UNVERIFIED**; documented for Phase 5. |

> **Generator caveat (important).** `scripts/_gen_env_example.py` is a **stale
> one-shot bootstrap** ("safe to delete after running") and has **drifted** from
> the committed `.env.example` — it is missing `CLOUDFLARE_OAUTH_SCOPES`,
> `CLOUDFLARE_SCANNER_OAUTH_SCOPES`, and `WEBHOUND_SCANNER_OUTBOUND_IPS`, and still
> carries the old single egress IP. Running it would **corrupt** `.env.example`.
> Because of this, Phase 1 did **not** add these keys to `.env.example` (to avoid
> dropping real config). To add them safely, first **re-sync the generator's
> `ROOT` template to the current `.env.example`**, then append these keys and
> regenerate — or add them directly to `.env.example` (it is the de-facto source
> of truth now; the harness protects `.env*` from the editing tools, so a human or
> the generator must write it).
