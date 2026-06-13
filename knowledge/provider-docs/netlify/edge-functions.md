# Netlify Edge Functions and Security

**Provider:** Netlify · **Authority:** Tier A official docs · **Source:** https://docs.netlify.com/edge-functions/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Netlify is

Netlify is a web hosting and serverless platform primarily used for static sites + serverless functions. Key components:
- **Edge Functions**: Deno-based runtime, runs before CDN cache at edge nodes
- **Netlify Functions**: Lambda-based (Node.js), runs at origin
- **Deploy Previews**: unique URLs per pull request (e.g., `deploy-preview-123--project.netlify.app`)
- **Forms**: built-in form handling

## Response headers from Netlify

| Header | Value |
|---|---|
| `server` | `Netlify` |
| `x-nf-request-id` | Unique per request (edge trace ID) |
| `cache-status` | `hit`, `miss`, `expired` |
| `netlify-vary` | Cache variation key |

## Deploy Preview access control

Deploy Previews are publicly accessible by default. Netlify offers:
- **Password protection**: basic auth on site (Pro plan required)
- **Netlify Identity**: JWT-based auth gate
- **Netlify Deploy Preview access**: specific to PR previews (requires deploy access token)

Scanner hitting a deploy preview URL with no auth protection gets the preview app.
Deploy preview URLs follow pattern: `https://deploy-preview-{PR#}--{site-name}.netlify.app`

## Edge Functions (security relevance)

Edge Functions can:
- Rewrite requests (URL manipulation, redirect logic)
- Add/remove headers (e.g., inject CSP, remove server header)
- Rate-limit by IP (custom logic)
- A/B test traffic (split by cookie/IP)

**Scanner implication:** if a site uses Edge Functions to inject security headers (CSP, HSTS), scanner sees these as Netlify-injected, not origin-set. The origin may not have these protections if not fronted by Netlify.

## Forms (potential attack surface)

Netlify Forms receive form submissions and store them in Netlify's dashboard.
Forms use a hidden `form-name` field and `netlify` attribute to opt in.
Scanner should check:
- Does the form have CSRF protection? (Netlify doesn't add CSRF tokens automatically)
- Is Netlify's spam filter (Akismet integration) active?
- Are submissions exposed via Netlify API (read submissions requires auth)?

## Identifying Netlify-hosted sites

- `server: Netlify` response header
- `x-nf-request-id` header
- Site URL ending in `.netlify.app`
- IP resolving to Netlify edge nodes (AS16509 Amazon if Netlify uses AWS, or Netlify's own AS)

**Related:** [[vercel-deployment-protection]], [[cloudflare-waf-detection]].
