---
title: Authentication
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 20 — Authentication

## Methods

| Method | Router | Notes |
|--------|--------|-------|
| Email/password | `routers/auth.py` | JWT-based |
| Google OAuth | `routers/oauth.py` | Social login |
| GitHub OAuth | `routers/oauth.py` | Social login |

## Flow

```
Email login: POST /auth/login → verify hash → JWT issued
Register:    POST /auth/register → user created → verify email
OAuth:       GET /oauth/{provider} → redirect → callback → user upsert → JWT
Refresh:     POST /auth/refresh → new JWT (short TTL)
```

## JWT

- Short-lived access tokens
- Refresh token rotation
- All protected routes require `Authorization: Bearer <token>`

## 2FA / Phone Verification

- `apps/api/routers/phone.py` — phone number verification
- `apps/api/services/sms.py` — SMS delivery

## Session Security

- `SecurityHeadersMiddleware` sets auth-relevant headers
- `RateLimitMiddleware` protects login endpoints from bruteforce
- `EncryptedSecret` model for provider token storage

## See Also

- [[04-Backend/index|Backend]] · [[20-Authentication/index|Auth]] · [[21-Billing/index|Billing]]
- [[06-Infrastructure/Railway|Railway]] (env vars for JWT secret)

#webhound #auth #index
