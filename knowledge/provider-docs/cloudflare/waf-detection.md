# Cloudflare WAF and Challenge Page Detection

**Provider:** Cloudflare · **Authority:** Tier A official docs · **Source:** https://developers.cloudflare.com/waf/
**Terms note:** Publicly available docs; detection-relevant summary only.

## Challenge page signatures

When Cloudflare challenges a request, the scanner receives one of:

| Challenge type | Status | Key response indicator |
|---|---|---|
| **Managed Challenge** | 403 or redirect | `cf-mitigated: challenge` response header |
| **JS Challenge** | 200 (JS page) | `cf-chl-bypass` cookie + JS spinner HTML |
| **Turnstile CAPTCHA** | 200 | Turnstile widget HTML with `data-sitekey` attribute |
| **Interactive Challenge** | 200 | CAPTCHA/interactive HTML from `challenges.cloudflare.com` |
| **IP Block** | 403 | Ray ID in HTML body + `cf-ray` header |

## Response headers set by Cloudflare edge

| Header | Always present | Value |
|---|---|---|
| `cf-ray` | Yes | Unique ray ID per request (e.g., `86abc123def456-IAD`) |
| `server` | Yes | `cloudflare` |
| `cf-cache-status` | Usually | `HIT`, `MISS`, `BYPASS`, etc. |
| `cf-mitigated` | On blocked req | `challenge` |
| `x-frame-options` | Some origins | May be injected by CF Workers |

## Bot Fight Mode / Super Bot Fight Mode

- Enabled per zone. When a request matches bot fingerprint, CF serves challenge or 403.
- Detection signals: JA3/JA4 TLS fingerprint, HTTP/2 SETTINGS frames, browser header order, request rate patterns.
- A scanner using a modern TLS stack (e.g., Go's `crypto/tls`) will have a different JA3 than a browser.
- Verified Bot allows: Googlebot, Bingbot, and ~dozen others listed at https://developers.cloudflare.com/bots/reference/verified-bots-list/

## Firewall rules / WAF managed rules

- OWASP-based managed ruleset (100+ rules), CloudFlare managed ruleset.
- SQL injection detection: rule group `Cloudflare:OWASP`, triggers on SQLi patterns in query params/body.
- XSS detection: rule group `Cloudflare:OWASP`, detects `<script>`, event handlers, encoded entities.
- If a rule triggers, response is 403 with `cf-ray` header; body contains ray ID.

## Scanner allowlisting (for WebHound)

Cloudflare official bypass approaches:
1. **Allowlist IP via WAF Bypass rule**: `ip.src in {x.x.x.x}` action = skip.
2. **Authenticated Origin Pulls**: mutual TLS between CF and origin.
3. **Cloudflare Access service token**: request header `CF-Access-Client-Id` + `CF-Access-Client-Secret`.
4. **Cloudflare Tunnel**: scanner reaches origin via private tunnel bypassing public edge.

WebHound has OAuth integration with Cloudflare → can create WAF bypass rule programmatically via Cloudflare API (`POST /zones/{zone_id}/firewall/rules`).

## HTTP/2 fingerprinting

Cloudflare uses HTTP/2 SETTINGS frame analysis to fingerprint clients. A scanner using urllib or curl default settings will produce a fingerprint distinct from Chrome/Firefox. To appear browser-like, scanner should send HTTP/2 with browser-matching SETTINGS values (HEADER_TABLE_SIZE=65536, ENABLE_PUSH=1, INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144).

**Related:** [[cloudflare-dns]], [[cloudflare-workers]], [[vercel-firewall]].
