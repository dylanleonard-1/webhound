---
title: Cloudflare
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Cloudflare

## Role

Cloudflare is both a **scanned provider** (customer sites behind CF WAF/CDN) and a source of **scanner access configuration** (to let WebHound through CF WAF).

## Scanner Access

- Services: `apps/api/services/cloudflare.py`, `cloudflare_rules.py`, `cloudflare_scanner_access.py`, `cloudflare_scanner_state.py`, `cloudflare_scopes.py`, `cloudflare_telemetry.py`
- Router: `apps/api/routers/cloudflare.py`
- Access patterns: IP allowlisting, firewall rule management

## Knowledge Corpus

9 engine notes from Cloudflare (authority tier A/B) covering:
- WAF bypass detection
- CDN behavior patterns
- Deployment protection

## Provider Data Model

- `ProviderConnection` with `provider = "cloudflare"`
- `ProviderProfile` for site-specific config
- `EncryptedSecret` stores API tokens

## See Also

- [[06-Infrastructure/index|Infrastructure]] · [[10-Providers/index|Providers]]
- [[07-Scanner/index|Scanner]] · [[05-Provider Intelligence/index|Provider Intel (8A)]]

#webhound #infrastructure #cloudflare
