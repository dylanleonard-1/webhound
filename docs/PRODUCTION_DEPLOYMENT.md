# WebHound — Production Deployment Guide

**Domain:** `webhoundsecurity.com`  
**App:** `app.webhoundsecurity.com` (Vercel)  
**API:** `api.webhoundsecurity.com` (VPS / Railway / Render)  

---

## 1. DNS Records (Cloudflare)

### Core records
| Type  | Name              | Value                          | Proxy |
|-------|-------------------|--------------------------------|-------|
| A     | `@`               | `<your-server-ip>`             | Yes   |
| CNAME | `www`             | `webhoundsecurity.com`         | Yes   |
| CNAME | `app`             | `cname.vercel-dns.com`         | No    |
| A     | `api`             | `<your-api-server-ip>`         | Yes   |

### Resend email DNS (add after connecting domain in Resend dashboard)
| Type  | Name                                | Value                              |
|-------|-------------------------------------|------------------------------------|
| TXT   | `resend._domainkey.webhoundsecurity.com` | `(from Resend dashboard)`     |
| TXT   | `@`                                 | `v=spf1 include:amazonses.com ~all`|
| CNAME | `em.webhoundsecurity.com`           | `(from Resend dashboard)`          |

---

## 2. Environment Variables

Copy `.env.example` to `.env.prod` and fill in all required values.

### Required for production
```bash
# Core
APP_ENV=production
SECRET_KEY=<32-byte hex — python3 -c "import secrets; print(secrets.token_hex(32))">
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/webhound
REDIS_URL=redis://host:6379/0

# URLs
API_BASE_URL=https://api.webhoundsecurity.com
FRONTEND_URL=https://webhoundsecurity.com
NEXT_PUBLIC_API_URL=https://api.webhoundsecurity.com
NEXT_PUBLIC_SITE_URL=https://webhoundsecurity.com

# CORS
CORS_ORIGINS=["https://webhoundsecurity.com","https://app.webhoundsecurity.com"]

# Resend (production email)
RESEND_API_KEY=re_xxxxxxxxxxxx
RESEND_FROM_EMAIL=auth@webhoundsecurity.com

# OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

---

## 3. OAuth Callback URLs

### Google OAuth
- Console: https://console.cloud.google.com/apis/credentials
- **Authorized JavaScript origins:**
  - `https://webhoundsecurity.com`
  - `https://app.webhoundsecurity.com`
- **Authorized redirect URIs:**
  - `https://api.webhoundsecurity.com/auth/oauth/google/callback`

### GitHub OAuth
- Settings: https://github.com/settings/developers → New OAuth App
- **Homepage URL:** `https://webhoundsecurity.com`
- **Authorization callback URL:** `https://api.webhoundsecurity.com/auth/oauth/github/callback`

### Apple OAuth (future)
- Portal: https://developer.apple.com/account/resources/identifiers/list/serviceId
- **Return URL:** `https://api.webhoundsecurity.com/auth/oauth/apple/callback`

---

## 4. Resend Setup

1. Sign up at https://resend.com
2. Add domain `webhoundsecurity.com` → follow DNS verification
3. Add DNS records from Resend dashboard to Cloudflare
4. Verify domain (takes up to 72h for propagation)
5. Create API key → set as `RESEND_API_KEY` env var
6. Verified sender addresses:
   - `auth@webhoundsecurity.com` — verification emails, login alerts
   - `noreply@webhoundsecurity.com` — transactional notifications
   - `support@webhoundsecurity.com` — support replies

---

## 5. Vercel Deployment

1. Connect repo to Vercel project
2. Set **Root Directory:** `apps/web`
3. Set **Build Command:** `next build`
4. Add environment variables in Vercel dashboard:
   ```
   NEXT_PUBLIC_API_URL=https://api.webhoundsecurity.com
   NEXT_PUBLIC_SITE_URL=https://webhoundsecurity.com
   ```
5. Add custom domains: `webhoundsecurity.com`, `app.webhoundsecurity.com`
6. Enable HTTPS (automatic with Vercel)

---

## 6. API Deployment (Docker)

```bash
# Build and start production stack
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d

# Run migrations
docker compose -f docker-compose.prod.yml exec api alembic -c apps/api/alembic.ini upgrade head

# Check health
curl https://api.webhoundsecurity.com/health
```

### Railway migrations (portfolio migration 0032 and later)

The API service deploys on Railway (see `railway.toml`). Run Alembic against
the Railway-injected `DATABASE_URL` with `railway run`:

```bash
# Readiness check FIRST — compare current DB revision against the code head.
railway run alembic -c apps/api/alembic.ini current      # DB's applied head
railway run alembic -c apps/api/alembic.ini heads         # code head (expect 0033)

# Apply all pending migrations up to head (idempotent; safe to re-run).
railway run alembic -c apps/api/alembic.ini upgrade head

# Confirm: `current` now equals `heads`.
railway run alembic -c apps/api/alembic.ini current
```

The portfolio feature (Phase-16 `website_groups` + `websites.group_id`) ships
in migration **0032**, which descends from 0031; the current head is **0033**
(notification email delivery). 0032 is purely additive and idempotent
(table/column-exists guards) — single-site users are unaffected because
`group_id` stays NULL. The chain (0001 → … → 0033, single linear path) is
verified statically by `apps/api/tests/test_migration_chain.py` and reported by
`scripts/audit_runtime_config.py`, neither of which opens a database.

---

## 7. Production Checklist

### Security
- [ ] `SECRET_KEY` changed from default (not `dev-secret-key-*`)
- [ ] `APP_ENV=production` set
- [ ] `DEBUG=false` set
- [ ] `DEV_ALLOW_UNVERIFIED_SCANS=false`
- [ ] `DEV_SKIP_DOMAIN_VERIFICATION=false`
- [ ] CORS origins set to production domains only
- [ ] HTTPS enforced (Vercel + Cloudflare)
- [ ] Cloudflare SSL mode: **Full (strict)**

### Database
- [ ] Postgres running with strong password (not `webhound/webhound`)
- [ ] Database backups enabled
- [ ] Migrations run: `alembic upgrade head`

### Email
- [ ] Resend domain verified
- [ ] Resend DNS records propagated
- [ ] Test verification email received from `auth@webhoundsecurity.com`

### OAuth
- [ ] Google OAuth app published (not in test mode)
- [ ] Google authorized origins point to `webhoundsecurity.com`
- [ ] GitHub OAuth callback URL updated
- [ ] OAuth flow tested end-to-end

### Monitoring
- [ ] Health endpoint responding: `GET /health`
- [ ] Worker healthy: `celery inspect ping`
- [ ] Sentry or similar error tracking configured (optional)

### Rate Limiting
- [ ] `RATE_LIMIT_ENABLED=true`
- [ ] `RATE_LIMIT_REQUESTS_PER_MINUTE` tuned for production load

---

## 8. Secrets Rotation

If credentials were shared in chat or committed accidentally, rotate immediately:
- Google OAuth secret → https://console.cloud.google.com/apis/credentials
- GitHub OAuth secret → https://github.com/settings/developers
- Twilio Auth Token → https://console.twilio.com
- SECRET_KEY → regenerate with `python3 -c "import secrets; print(secrets.token_hex(32))"`

---

## 9. Email Address Reference

| Address                          | Purpose                        |
|----------------------------------|--------------------------------|
| auth@webhoundsecurity.com        | Verification, login alerts     |
| noreply@webhoundsecurity.com     | Transactional emails           |
| support@webhoundsecurity.com     | Support contact                |
| security@webhoundsecurity.com    | Vulnerability disclosures      |
| privacy@webhoundsecurity.com     | Data/privacy requests          |
| legal@webhoundsecurity.com       | Legal inquiries                |
| hello@webhoundsecurity.com       | General contact                |
