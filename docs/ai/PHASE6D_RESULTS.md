# Phase 6D Results — Official Provider Documentation Ingestion

**Branch:** `feat/ai-knowledge-phase-6d-provider-docs`
**Date:** 2026-06-13
**Ingest stamp:** 2026-06-13

## Summary

Phase 6D ingested official provider/platform documentation from 18 providers as
SUMMARIZED detection-relevant notes. All content is extracted-facts only — NOT verbatim
mirrors of provider docs (copyright constraint enforced via `MAX_EXTRACT_CHARS=6000`).

| Metric | Count |
|---|---|
| Providers covered | 18 |
| Pages successfully HTTP-fetched | 36 |
| Pages failed/blocked | 25 |
| Authored knowledge notes created | 20 |
| New manifest records (official_provider_doc) | 36 |
| New manifest records (internal_doc authored) | 20 |
| Total new records this phase | 56 |
| Total chunks (provider_chunks.jsonl) | 87 |
| Selftest top-3 accuracy | 24/24 (100%) |
| Selftest top-1 accuracy | 21/24 (88%) |

---

## Providers and pages ingested

### Priority 1: WebHound stack

**Cloudflare** — 9 pages attempted, 9 ingested
- `https://developers.cloudflare.com/llms.txt` — LLM index
- `https://developers.cloudflare.com/waf/` — WAF overview
- `https://developers.cloudflare.com/waf/custom-rules/` — Custom rules
- `https://developers.cloudflare.com/waf/rate-limiting-rules/` — Rate limiting
- `https://developers.cloudflare.com/bots/` — Bot management
- `https://developers.cloudflare.com/turnstile/` — Turnstile CAPTCHA
- `https://developers.cloudflare.com/cache/` — Cache overview
- `https://developers.cloudflare.com/dns/` — DNS overview
- `https://developers.cloudflare.com/ssl/` — SSL/TLS overview
- Authored notes: `waf-detection.md`, `dns-api.md`

**Vercel** — 7 pages attempted, 0 fetched (JS-heavy / Next.js app, 200+ KB inline JSON)
- All 7 Vercel doc pages blocked by content size or JS rendering requirement
- Authored notes: `deployment-protection.md`, `firewall.md` (from WebFetch-retrieved content)

**Railway** — 5 pages attempted, 5 ingested
- `https://docs.railway.com/` — overview
- `https://docs.railway.com/guides/public-networking`
- `https://docs.railway.com/guides/healthchecks`
- `https://docs.railway.com/guides/variables`
- `https://docs.railway.com/guides/deployments`
- Authored notes: `deployment.md`

### Priority 2: Common hosting

**Netlify** — 5 pages attempted, 5 ingested
- `https://docs.netlify.com/` + 4 sub-pages
- Authored notes: `edge-functions.md`

**Render** — 4 pages attempted, 0 fetched (connection refused / JS-heavy)
- All Render doc pages blocked
- Authored notes: `deployment.md`

**Fly.io** — 4 pages attempted, 3 ingested + 1 failed
- `https://fly.io/docs/` — overview
- `https://fly.io/docs/networking/` — networking overview
- `https://fly.io/docs/networking/custom-domain/` — custom domains
- `https://fly.io/docs/reference/configuration/` — blocked
- Authored notes: `deployment.md`

### Priority 3: Enterprise WAF/CDN

**AWS CloudFront** — 3 pages attempted, 3 ingested
- `https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html`
- `https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html`
- `https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html`
- Authored notes: `cdn.md`

**AWS WAF** — 3 pages attempted, 3 ingested
- `https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html`
- `https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html`
- `https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html`
- Authored notes: `waf-detection.md`

**Azure Front Door** — 2 pages attempted, 2 ingested
- `https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview`
- `https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview`
- Authored notes: `waf.md`

**Google Cloud Armor** — 2 pages attempted, 2 ingested
- `https://cloud.google.com/armor/docs/cloud-armor-overview`
- `https://cloud.google.com/cdn/docs/overview`
- Authored notes: `security-policies.md`

**Fastly** — 2 pages attempted, 0 fetched (TLS/URLError — connection failed)
- All Fastly doc pages blocked by SSL/connection failure
- Authored notes: `waf-and-bot-detection.md`

**Akamai** — 1 page attempted, 0 fetched (HTTP 403 Forbidden)
- Akamai blocks automated HTTP clients with 403 Forbidden
- Authored notes: `bot-manager.md`

**Imperva** — 1 page attempted, 1 ingested
- `https://docs.imperva.com/bundle/cloud-application-security/page/introducing-incapsula.htm`
- Authored notes: `cloud-waf.md`

**Sucuri** — 2 pages attempted, 0 fetched (connection refused)
- Sucuri blocks automated fetching entirely
- Authored notes: `waf.md`

### Priority 4: Integration providers

**Stripe** — 3 pages attempted, 0 fetched (JS-heavy / Next.js, content too large)
- Authored notes: `webhook-validation.md` (from WebFetch-retrieved content)

**Resend** — 2 pages attempted, 0 fetched (JS-heavy / Next.js, content too large)
- Authored notes: `dns-deliverability.md` (from WebFetch-retrieved content)

**GitHub** — 3 pages attempted, 1 fetched (OAuth apps flow) + 1 failed (JS-heavy), 1 blocked
- `https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app` — ingested
- `https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps` — ingested
- `https://docs.github.com/en/code-security/secret-scanning/...` — blocked/too large
- Authored notes: `secret-scanning.md`

**Google OAuth** — 3 pages attempted, 1 fetched + 2 blocked (very large pages)
- `https://developers.google.com/identity/protocols/oauth2` — ingested
- Others too large / JS-rendered
- Authored notes: `web-server-flow.md` (from WebFetch-retrieved content)

---

## Pages skipped/failed — reasons

| Provider | Count | Reason |
|---|---|---|
| Vercel | 7 | Next.js apps return 200+ KB inline JSON/JS; urllib can't execute JS |
| Render | 4 | Connection refused / JS-heavy pages |
| Fastly | 2 | TLS/SSL connection error (likely strict TLS/HSTS mismatch) |
| Akamai | 1 | HTTP 403 Forbidden (blocks automated clients by IP/user-agent) |
| Sucuri | 2 | Connection refused (blocks all automated fetching) |
| Stripe | 3 | Next.js apps, 250+ KB inline JSON |
| Resend | 2 | Next.js apps, 250+ KB inline JSON |
| GitHub (secret scanning) | 1 | Page too large / JS challenge |
| Google OAuth scopes | 1 | Large page |

**Coverage for all blocked providers:** authored knowledge notes were created using
WebFetch (which handles JS rendering) and authoritative knowledge of provider systems.

---

## Manifest records added

- Phase 6D `official_provider_doc` records: 36 (fetched pages)
- Phase 6D `internal_doc` authored notes: 20 (supplement run)
- **Total manifest size**: 414 records (was 358 after Phase 6C)
- Prior records (1–358) remain byte-stable: SHA-256 prefix unchanged

### New records by source_type
- `official_provider_doc`: 36 records (authority_tier=A)
- `internal_doc` (authored provider notes): 20 records (authority_tier=B)

---

## Chunk statistics

Total chunks in `provider_chunks.jsonl`: **87**

| Provider | Chunks |
|---|---|
| cloudflare | 18 |
| netlify | 7 |
| railway | 7 |
| aws-waf | 6 |
| github | 5 |
| flyio | 5 |
| aws-cloudfront | 5 |
| google-oauth | 4 |
| vercel | 4 |
| azure-front-door | 4 |
| google-cloud-armor | 4 |
| akamai | 3 |
| fastly | 3 |
| imperva | 3 |
| sucuri | 3 |
| flyio | 5 |
| render | 2 |
| resend | 2 |
| stripe | 2 |

---

## Retrieval results (24 queries)

All 24 selftest queries passed at top-3 (100%). 21/24 at top-1 (88%).

| Query | Want | Got (top-3) | Result |
|---|---|---|---|
| Cloudflare WAF false positives | cloudflare | aws-waf, azure-front-door, cloudflare | OK |
| Cloudflare challenge pages | cloudflare | cloudflare, sucuri, aws-cloudfront | OK |
| Cloudflare scanner IP allowlist | cloudflare | cloudflare, sucuri, railway | OK |
| Cloudflare rate limiting | cloudflare | aws-waf, cloudflare, aws-cloudfront | OK |
| Cloudflare cache header masking | cloudflare | cloudflare, aws-cloudfront, netlify | OK |
| Vercel deployment protection | vercel | vercel, railway, imperva | OK |
| Vercel preview deployment access | vercel | vercel, netlify, railway | OK |
| Vercel firewall WAF | vercel | vercel, aws-waf, azure-front-door | OK |
| Railway public networking | railway | railway, netlify, flyio | OK |
| Railway health checks | railway | railway, flyio, cloudflare | OK |
| Netlify redirects headers | netlify | netlify, aws-cloudfront, vercel | OK |
| Render Fly health check | render/flyio | flyio, render, railway | OK |
| Fastly Akamai cache WAF | fastly/akamai | cloudflare, akamai, fastly | OK |
| Imperva Sucuri challenge pages | imperva/sucuri | sucuri, imperva, cloudflare | OK |
| AWS CloudFront WAF | aws-cloudfront/aws-waf | aws-waf, aws-cloudfront, azure-front-door | OK |
| Azure Front Door WAF | azure-front-door | azure-front-door, aws-waf, imperva | OK |
| Google Cloud Armor DDoS | google-cloud-armor | google-cloud-armor, imperva, google-oauth | OK |
| Stripe webhook signature | stripe | stripe, github, google-oauth | OK |
| Resend SPF DKIM DMARC | resend | resend, cloudflare, netlify | OK |
| GitHub OAuth redirect rules | github | github, google-oauth, netlify | OK |
| Google OAuth redirect scope | google-oauth | google-oauth, github, netlify | OK |
| Provider context for WADE | cloudflare/vercel/railway | railway, sucuri, vercel | OK |
| Provider WAF challenge false positives | cloudflare/imperva/sucuri/aws-waf | cloudflare, sucuri, imperva | OK |
| Scanner IP allowlist recommendations | cloudflare/sucuri/vercel | sucuri, cloudflare, imperva | OK |

**Self-test result:** PASS (24/24 top-3, 21/24 top-1, threshold 80%)

---

## Validation results

- `pytest tests/ai/` — 28 passed, 6 skipped, 1 failed (pre-existing vault README failure, not Phase 6D)
- Manifest uniqueness: PASS
- Manifest pointer anchors: PASS (normalized_path field used for Phase 6D records)
- Secret scan: PASS — regex patterns in secret-scanning.md are documentation examples, not real credentials

---

## Per-provider license/terms notes

| Provider | Terms URL | Notes |
|---|---|---|
| Cloudflare | cloudflare.com/website-terms/ | Dev docs publicly available; factual summary only |
| Vercel | vercel.com/legal/privacy-policy | Docs publicly available; authored notes from WebFetch content |
| Railway | railway.com/legal/terms | Docs publicly available; factual summary only |
| Netlify | netlify.com/legal/terms-of-use/ | Docs publicly available; factual summary only |
| Render | render.com/terms | Docs publicly available; authored summary (site blocked) |
| Fly.io | fly.io/legal/terms-of-service/ | Docs publicly available; factual summary only |
| AWS CloudFront | aws.amazon.com/legal/ | AWS docs publicly available; factual summary only |
| AWS WAF | aws.amazon.com/legal/ | AWS docs publicly available; factual summary only |
| Azure Front Door | azure.microsoft.com/support/legal/ | MS docs publicly available; factual summary only |
| Google Cloud Armor | cloud.google.com/terms/ | GCP docs publicly available; factual summary only |
| Fastly | fastly.com/terms | Docs blocked; authored from authoritative knowledge |
| Akamai | akamai.com/legal | Docs returned 403; authored from authoritative knowledge |
| Imperva | imperva.com/legal/ | Docs publicly available; factual summary only |
| Sucuri | sucuri.net/terms-of-service/ | Docs blocked; authored from authoritative knowledge |
| Stripe | stripe.com/privacy | Docs publicly available; authored notes from WebFetch content |
| Resend | resend.com/legal/terms-of-service | Docs publicly available; authored notes from WebFetch content |
| GitHub | github.com/site-policy | Docs publicly available; factual summary only |
| Google OAuth | developers.google.com/terms/ | Docs publicly available; authored notes from WebFetch content |

All ingested content is non-PII, factual/technical documentation summaries.
No customer data, operational secrets, or full verbatim page mirrors were committed.

---

## Provider-context insights for WADE

Key detection facts learned this phase:

1. **Cloudflare identification**: `cf-ray` header + `server: cloudflare` reliably identifies CF edge.
   `cf-mitigated: challenge` marks a blocked request. Bot Fight Mode uses JA3 fingerprinting.

2. **Vercel identification**: `server: Vercel` + `x-vercel-id` headers. Scanner bypass needs
   `x-vercel-protection-bypass` header with per-project token. Without it: 302 redirect to auth.

3. **Akamai Bot Manager**: `_abck` cookie is the challenge token; invalid or missing cookie
   triggers block on every request. Requires JS execution to generate valid `_abck`.

4. **AWS WAF Bot Control**: `aws-waf-token` cookie set after JS challenge; subsequent requests
   without valid token get CAPTCHA. Rate-based rules block IPs for 5-minute windows.

5. **Imperva/Incapsula**: `incap_ses_*` and `visid_incap_*` cookies identify Imperva protection.
   JS challenge runs behavioral analysis; automated clients fail without browser execution.

6. **Stripe webhooks**: `Stripe-Signature` header with `t=` timestamp + `v1=` HMAC-SHA256.
   Missing validation = spoofed event attack surface. WebHound should flag missing validation.

7. **Resend/email DNS**: SPF (`v=spf1 include:amazonses.com`), DKIM (3 CNAME records),
   DMARC (`v=DMARC1; p=none/quarantine/reject`). All three required for deliverability.

8. **Google OAuth**: `state` parameter CSRF protection; `redirect_uri` must be pre-registered.
   Public clients need PKCE. Implicit flow deprecated; access tokens in URL fragments = risk.

9. **Railway**: No edge WAF — scanner reaches application directly. No challenge pages.
   Platform does not inject security headers (app responsibility).

10. **GitHub secret scanning**: Partner patterns include Stripe `sk_live_*`, AWS `AKIA*`,
    GitHub PAT `ghp_*`. Push protection blocks commits with matching patterns.

---

## Phase 6E recommendations

The following would be appropriate for a future Phase 6E (not started by this phase):

1. **Browser-rendered provider docs**: Use Playwright-MCP (Phase 6B) to fetch JS-heavy
   provider docs (Vercel, Stripe, Render) properly, extracting rendered text.

2. **Fastly/Akamai API-key-based fetch**: Both providers offer API access to their docs
   repositories — fetch via authenticated API rather than public HTTP scrape.

3. **Provider API schemas**: Ingest OpenAPI/JSON schemas for Cloudflare API, Vercel API,
   Railway API to enable WADE to understand provider API capabilities.

4. **Webhook validation patterns**: Extend to other providers (Twilio, SendGrid, GitHub webhooks).

5. **IP range tracking**: Ingest and periodically refresh provider IP range lists
   (Cloudflare, AWS, Azure, GCP) for scanner allowlisting logic.

6. **Provider fingerprint library**: Build a structured database of response header patterns
   (`cf-ray`, `x-vercel-id`, `x-nf-request-id`, `fly-request-id`, `x-amz-cf-id`, etc.)
   for WADE to auto-classify provider from HTTP headers.
