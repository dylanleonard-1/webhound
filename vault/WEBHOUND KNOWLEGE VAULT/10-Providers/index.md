---
title: Providers
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 10 — Providers

→ Existing Phase 8A coverage: [[10-Providers/Provider Intelligence Overview|Provider Overview]] · [[10-Providers/CDN Providers|CDN]] · [[10-Providers/Cloud Providers|Cloud]] · [[10-Providers/WAF Providers|WAF]]

## Provider Knowledge in Corpus

| Provider | Records | Type |
|----------|---------|------|
| Cloudflare | 9 | engine_note + provider_note |
| Vercel | 7 | engine_note + provider_note |
| Railway | 5 | provider_note |
| Netlify | 5 | provider_note |
| Others | 14 | various |

## Infrastructure Integration

| Provider | Role |
|----------|------|
| Cloudflare | Scanned WAF/CDN + scanner access bypass |
| Vercel | Frontend host + scanner access bypass |
| Railway | Backend + DB host |
| Stripe | Billing |
| Resend | Email delivery |

## DB Models

- `ProviderConnection` — org-level OAuth/API connection
- `ProviderProfile` — site-level provider config
- `EncryptedSecret` — token vault
- `apps/api/services/provider_access_registry.py` — allowlist management

## See Also

- [[06-Infrastructure/Cloudflare|Cloudflare]] · [[06-Infrastructure/Vercel|Vercel]]
- [[07-Scanner/index|Scanner]] · [[21-Billing/index|Billing]]

#webhound #providers #index

## Merged from Phase 8A (05-Provider Intelligence)

- [[10-Providers/CDN Providers|CDN Providers]]
- [[10-Providers/Cloud Providers|Cloud Providers]]
- [[10-Providers/Provider Intelligence Overview|Provider Intelligence Overview]]
- [[10-Providers/WAF Providers|WAF Providers]]
