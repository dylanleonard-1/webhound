# Stripe Webhooks — Complete Technical Reference

Source: https://docs.stripe.com/webhooks
Provider: Stripe | Authority: Tier A
Ingested: 2026-06-13 | Terms: Stripe docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Overview

Stripe sends HTTP POST requests to configured webhook endpoints when payment events occur. Every POST contains a JSON Event object payload.

## Handler requirements

1. Accept POST requests with JSON payload
2. Return `2xx` status code immediately before complex processing
3. Must use HTTPS for production (HTTP acceptable for local development only)
4. TLS v1.2 or v1.3 minimum

## Stripe-Signature header

Every webhook POST includes a `Stripe-Signature` header:

```
Stripe-Signature: t=1492774577,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39
```

- `t` — Unix timestamp of when signature was generated
- `v1` — HMAC-SHA256 signature (current scheme)
- `v0` — legacy SHA1 signature (test-only, deprecated; discard in production)

Multiple `v1` values appear during secret rolling transitions.

## Manual signature verification algorithm

**Step 1:** Split header by `,`; extract `t=` value and `v1=` value(s). Discard `v0`.

**Step 2:** Construct signed payload: `signed_payload = timestamp + "." + request_body`

**Step 3:** Compute expected signature: `expected = HMAC-SHA256(endpoint_secret, signed_payload)`

**Step 4:** Compare using constant-time string comparison. Check `|current_time - t| < tolerance` (default 5 minutes). Do NOT use tolerance of 0.

**Critical:** Use the raw request body bytes before any JSON parsing. Frameworks that automatically parse/mutate bodies (Express, Next.js, AWS Lambda) break verification. Must preserve exact UTF-8 bytes Stripe sends.

## Endpoint secret format

The `endpoint_secret` starts with `whsec_`. Different for Dashboard-managed vs CLI endpoints; do not mix secrets between sources.

## Event delivery and retries

- **Live mode:** retries up to 3 days with exponential backoff
- **Sandbox:** retries 3 times over a few hours
- Retry intervals: after 5m, 30m, 2h, 5h, 10h, 24h (Live mode)
- Manual resend via Dashboard (up to 15 days) or CLI (up to 30 days)

## HTTP status codes for troubleshooting

| Status | Issue | Solution |
|---|---|---|
| 200 | Success | — |
| ERR (unable to connect) | Can't reach server | Ensure publicly accessible |
| 302/3xx | Redirect | Update to resolved URL |
| 400/4xx | Server error or access restriction | Verify public endpoint, accepts POST |
| 500/5xx | Server processing error | Check application logs |
| TLS error | SSL/TLS issue | Require TLS v1.2+; run SSL test |
| Timeout | Response too slow | Return 200 immediately; defer processing |

## Event ordering

Events are NOT guaranteed to arrive in order. Do not depend on event ordering; use the API to retrieve missing objects.

## Idempotency

Stripe may deliver the same event multiple times. Handlers MUST be idempotent. Use `event.id` (or combination of `event.id + event.type`) as idempotency key.

## Security best practices

- Verify `Stripe-Signature` on every webhook request (missing validation = spoofed event attack surface)
- Use constant-time string comparison (`hmac.compare_digest()` in Python, never `==`)
- Validate timestamp tolerance to prevent replay attacks (default 5-minute window)
- Keep server clock synchronized via NTP
- Roll endpoint signing secrets periodically (via Dashboard overflow menu)
- Restrict to Stripe IP addresses as defense-in-depth: https://docs.stripe.com/ips

## WebHound scanner detection relevance

When scanning applications that use Stripe webhooks:
- Endpoint missing `Stripe-Signature` validation = critical security finding (spoofed event attack)
- Endpoint using string equality comparison for signatures = timing attack surface
- Endpoint without timestamp tolerance check = replay attack surface
- Endpoint parsing JSON before signature verification = body mutation risk

## Maximum endpoints

Up to 16 webhook endpoints per Stripe account.
