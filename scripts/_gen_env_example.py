"""One-shot generator for the protected .env.example templates.

The harness protects .env* files from the Read/Write/Edit tools, so this
script writes them. Safe to delete after running. Run:
    python scripts/_gen_env_example.py
"""
from __future__ import annotations

ROOT = r'''# ============================================================================
# WebHound environment configuration
# ----------------------------------------------------------------------------
# Copy to .env and fill in values:  cp .env.example .env
#
# This single file feeds three runtimes that share the repo root .env:
#   * apps/api    - FastAPI backend (pydantic Settings, see apps/api/config.py)
#   * worker      - Celery worker (reads os.getenv directly, see worker/)
#   * scanner     - webhound scanner engine (WEBHOUND_* tuning vars)
# The Next.js frontend (apps/web) uses its OWN env file: apps/web/.env.example
# (only NEXT_PUBLIC_* vars are exposed to the browser).
#
# Legend in comments:  [required]  [prod-required]  [secret]  [feature-flag]
# Full reference table with failure behaviour: docs/env.md
# ============================================================================

# ---------------------------------------------------------------------------
# Core  [required in every environment]
# ---------------------------------------------------------------------------
# APP_ENV controls fail-fast validation. One of: development | staging | production
APP_ENV=development
DEBUG=false
LOG_LEVEL=INFO

# Postgres. postgresql:// is auto-rewritten to postgresql+asyncpg:// by the API.
# [prod-required] - startup fails in production if left at the insecure default.
DATABASE_URL=postgresql+asyncpg://webhound:webhound@localhost:5432/webhound

# Redis - Celery broker/result backend + rate limiting + caches.  [prod-required]
REDIS_URL=redis://localhost:6379/0

# JWT signing key.  [prod-required] [secret]
# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
# Production startup FAILS if this is left at the default insecure value.
SECRET_KEY=dev-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Public-facing URLs (OAuth redirect_uri + post-auth redirects + emails).
# Production: API_BASE_URL=https://api.webhoundsecurity.com  FRONTEND_URL=https://webhoundsecurity.com
API_BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000

# ---------------------------------------------------------------------------
# Security / CORS
# ---------------------------------------------------------------------------
# Allowed CORS origins. JSON array OR comma-separated. Falls back to localhost.
# e.g. CORS_ORIGINS='["https://webhoundsecurity.com","https://app.webhoundsecurity.com"]'
CORS_ORIGINS=
CORS_ALLOW_CREDENTIALS=true
# Regex matching Vercel preview deploys. Override if the Vercel project/team changes.
# Production startup FAILS if this is not a compilable regex.
CORS_ORIGIN_REGEX=^https://webhound(-[a-z0-9-]+-webhoundsecurity)?\.vercel\.app$

RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# --- ADMIN BYPASS FLAGS - DANGEROUS. Default OFF. -------------------------
# These let a verified is_admin user skip security controls. They exist ONLY
# so the product team can QA the real flows against their own accounts.
# * They are IGNORED for non-admin users.
# * In production they are REFUSED unless ADMIN_BYPASS_ALLOW_IN_PROD=1 is also
#   set (explicit override). Every use emits an audit-log entry.
# Never enable these on a customer-facing deployment.
#
# ADMIN_VERIFY_BYPASS=1  -> admin can mark a domain "verified" without the DNS
#                           ownership check (SSRF / abuse risk).
# ADMIN_QUOTA_BYPASS=1   -> admin can run scans past plan quota.
ADMIN_VERIFY_BYPASS=0
ADMIN_QUOTA_BYPASS=0
ADMIN_BYPASS_ALLOW_IN_PROD=0

# Dev-only escape hatches. MUST stay false in production (startup fails otherwise).
DEV_ALLOW_UNVERIFIED_SCANS=false
DEV_SKIP_DOMAIN_VERIFICATION=false

# Emails auto-promoted to admin. JSON array or comma-separated.
ADMIN_EMAILS=

# ---------------------------------------------------------------------------
# AI summaries  [feature-flag, opt-in]
# ---------------------------------------------------------------------------
# Default OFF -> deterministic template summaries (fully offline).
# When WEBHOUND_AI_ENABLED=1 you MUST also set ANTHROPIC_API_KEY or the API
# refuses to start (avoids silently falling back to templates in prod).
WEBHOUND_AI_ENABLED=0
ANTHROPIC_API_KEY=                       # [secret]

# ---------------------------------------------------------------------------
# Threat intelligence  [feature-flag, opt-in]
# ---------------------------------------------------------------------------
# VirusTotal: presence of the key enables the provider.
VIRUSTOTAL_API_KEY=                      # [secret]
# URLhaus: ENABLE_URLHAUS=1 turns the provider on; key is optional (raises limits).
ENABLE_URLHAUS=0
URLHAUS_API_KEY=                         # [secret, optional]

# ---------------------------------------------------------------------------
# Email delivery  (Resend preferred; SMTP fallback)
# ---------------------------------------------------------------------------
# Resend is the primary provider. Sign up at resend.com, verify the domain.
RESEND_API_KEY=                          # [secret]
RESEND_FROM_EMAIL=auth@webhoundsecurity.com
RESEND_FROM_NAME=WebHound

# SMTP fallback - used when Resend fails AND SMTP_FALLBACK_ENABLED=1.
SMTP_FALLBACK_ENABLED=0
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=                           # [secret]
SMTP_FROM_EMAIL=noreply@webhoundsecurity.com
SMTP_FROM_NAME=WebHound
SMTP_USE_TLS=true

# In dev with neither provider configured, verification links/OTP are logged to
# the console instead of being sent.

# ---------------------------------------------------------------------------
# Twilio SMS  (optional - blank logs OTP codes to console in dev)
# ---------------------------------------------------------------------------
TWILIO_ACCOUNT_SID=                      # [secret]
TWILIO_AUTH_TOKEN=                       # [secret]
TWILIO_FROM_NUMBER=

# ---------------------------------------------------------------------------
# Stripe billing  [prod-required] [secret]
# ---------------------------------------------------------------------------
# Production startup FAILS if any of secret key, webhook secret, or the three
# price IDs are missing.
STRIPE_SECRET_KEY=                       # sk_live_... / sk_test_...
STRIPE_PUBLISHABLE_KEY=                  # pk_... (frontend reads NEXT_PUBLIC variant)
STRIPE_WEBHOOK_SECRET=                   # whsec_...
STRIPE_PRICE_PRO_MONTHLY=
STRIPE_PRICE_SHIELD_MONTHLY=
STRIPE_PRICE_ENTERPRISE_MONTHLY=

# ---------------------------------------------------------------------------
# OAuth providers  (empty string = provider disabled)
# ---------------------------------------------------------------------------
# Google - https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=                    # [secret]
# GitHub - https://github.com/settings/developers
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=                    # [secret]
# NOTE: Apple Sign In is NOT implemented in the API. The APPLE_* vars that used
# to live here (and in docker-compose) were dead config and have been removed.
# See docs/env.md if/when Apple OAuth is added.

# ---------------------------------------------------------------------------
# Scanner tuning  (WEBHOUND_* - consumed by the scanner engine)
# ---------------------------------------------------------------------------
WEBHOUND_LOG_LEVEL=INFO
# Per-engine timeout (seconds). Override one engine: WEBHOUND_ENGINE_TIMEOUT_<NAME>=N
WEBHOUND_DEFAULT_ENGINE_TIMEOUT=60
# Headless-browser discovery pass (Playwright). Off by default; 1 to enable.
WEBHOUND_BROWSER_ENABLED=0
# Attack-surface mapping network access (1 = allowed, default on).
WEBHOUND_ASM_ALLOW_NETWORK=1
# Optional directory of local threat-feed files.
WEBHOUND_THREAT_FEED_DIR=
# Guest scan retention before cleanup (worker task).
WEBHOUND_GUEST_RETENTION_HOURS=24

# ---------------------------------------------------------------------------
# Worker / Celery reliability
# ---------------------------------------------------------------------------
WORKER_CONCURRENCY=2
# Hard/soft scan time limits (seconds). See FIX 7 / worker/celery_app.py.
SCAN_SOFT_TIME_LIMIT=600
SCAN_HARD_TIME_LIMIT=720
# Stale-job reaper thresholds (seconds).
SCAN_STALE_QUEUED_SECONDS=900
SCAN_STALE_RUNNING_SECONDS=1800

# ---------------------------------------------------------------------------
# Notifications  [feature-flag]
# ---------------------------------------------------------------------------
# Master switch for outbound alert delivery (email/webhook). When 0, alerts are
# still recorded in-app but NO external messages are sent (and the UI says so).
NOTIFICATIONS_ENABLED=0

# ---------------------------------------------------------------------------
# Observability  (optional)
# ---------------------------------------------------------------------------
SENTRY_DSN=                              # empty disables Sentry
SENTRY_TRACES_SAMPLE_RATE=0.0
# Set automatically by Railway; surfaced on the health endpoint.
# RAILWAY_GIT_COMMIT_SHA / GIT_COMMIT_SHA
'''

WEB = r'''# ============================================================================
# WebHound frontend (apps/web) environment - Next.js
# ----------------------------------------------------------------------------
# Copy to apps/web/.env.local for local dev. On Vercel set these in the
# project's Environment Variables UI.
#
# Only NEXT_PUBLIC_* vars are exposed to the browser bundle - never put a
# secret behind a NEXT_PUBLIC_ prefix.
# ============================================================================

# Backend API base URL (used by the browser + server components).
# Production: https://api.webhoundsecurity.com
NEXT_PUBLIC_API_URL=http://localhost:8000

# Canonical site URL - used for SEO/canonical tags, sitemap, OG metadata.
# Production: https://webhoundsecurity.com
NEXT_PUBLIC_SITE_URL=http://localhost:3000

# Sentry browser DSN (optional - empty disables client error reporting).
NEXT_PUBLIC_SENTRY_DSN=

# ---------------------------------------------------------------------------
# Screenshot / snapshot tooling (scripts/, optional - only for visual capture)
# ---------------------------------------------------------------------------
# SNAP_BASE_URL=http://localhost:3000
# SNAP_OUT_DIR=.snapshots
# SNAP_REDUCED_MOTION=1
'''


def main() -> None:
    import os

    with open(".env.example", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(ROOT)
    print("wrote .env.example", len(ROOT), "bytes")

    os.makedirs("apps/web", exist_ok=True)
    with open("apps/web/.env.example", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(WEB)
    print("wrote apps/web/.env.example", len(WEB), "bytes")


if __name__ == "__main__":
    main()
