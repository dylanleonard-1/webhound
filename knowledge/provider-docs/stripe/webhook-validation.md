# Stripe Webhooks and Signature Validation

**Provider:** Stripe · **Authority:** Tier A official docs · **Source:** https://stripe.com/docs/webhooks
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Stripe webhooks deliver

Stripe sends HTTP POST requests to configured webhook endpoints when payment events occur.
Every webhook POST includes a `Stripe-Signature` header that must be validated before
processing the payload. Failing to validate opens the endpoint to spoofed events.

## Stripe-Signature header format

```
Stripe-Signature: t=1614556800,v1=abc123...,v0=def456...
```

- `t` — Unix timestamp of when the signature was generated (seconds)
- `v1` — HMAC-SHA256 signature (primary, current scheme)
- `v0` — SHA1 signature (legacy, deprecated; not used in current integrations)

Multiple `v1` values may appear (Stripe rotates secrets during key rollover):
```
Stripe-Signature: t=1614556800,v1=abc123...,v1=xyz789...
```

## HMAC-SHA256 validation algorithm

```
1. Parse t= and v1= values from the header
2. signed_payload = t + "." + raw_request_body (bytes)
3. expected_sig = HMAC-SHA256(webhook_secret, signed_payload)
4. Compare expected_sig to each v1= value using constant-time comparison
5. Check that |current_time - t| < tolerance (Stripe default: 300 seconds)
```

The `webhook_secret` is the `whsec_...` value from Stripe Dashboard.

**Critical:** use the **raw request body bytes** before any JSON parsing. Parsers may
normalize whitespace, changing the payload and breaking signature verification.

## Retry behavior

Stripe retries failed webhooks (non-2xx or no response) with exponential backoff:
- Next attempt after: 5m, 30m, 2h, 5h, 10h, 24h (up to ~72 hours)
- Events with `created` timestamp older than 72 hours are not retried further

A scanner testing a webhook endpoint should return 200 quickly or Stripe marks it as failing.

## Idempotency

Stripe may deliver the same event multiple times. Webhook handlers MUST be idempotent.
Use `event.id` as the idempotency key in the application's database.

## Webhook security hardening (detection relevance)

WebHound scans webhook endpoints for:
- Missing `Stripe-Signature` validation (attacker can send spoofed events)
- Timing-sensitive comparison (use `hmac.compare_digest()`, not `==`)
- Raw body re-encoding before comparison (must preserve original bytes)
- Missing timestamp tolerance check (replay attack surface)
- Endpoint not restricted to Stripe IP ranges (mitigated by signature; defense-in-depth: Stripe publishes its IP ranges at https://stripe.com/docs/ips)

**Related:** [[resend-dns-deliverability]], [[stripe-payment-flows]].
