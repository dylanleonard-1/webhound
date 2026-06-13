# Protection Bypass for Automation — Vercel

Source: https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Protection Bypass for Automation enables automated tests, CI/CD pipelines, and monitoring tools to access protected deployments without triggering authentication challenges or security blocks.

## How it works

Provide a valid bypass token and Vercel allows the request to access the deployment without authentication.

## What gets bypassed

- Password Protection
- Vercel Authentication
- Trusted IPs checks
- Vercel Firewall blocks (system mitigations that would normally block)
- Bot protection challenges

## What does NOT get bypassed

- Active DDoS mitigation IP blocks (if Vercel blocks an IP due to attack, bypass token cannot override)
- Rate limits applied during detected attacks
- Security challenges triggered by attack patterns

## Configuration

Multiple bypass secrets allowed per project (e.g., separate secrets for "CI/CD" and "Playwright tests").

Vercel automatically sets one secret as the `VERCEL_AUTOMATION_BYPASS_SECRET` system environment variable in deployments.

Secrets are per-project; regenerating/deleting the secret in project settings invalidates previous deployments. Must redeploy to use new secret value.

## Method 1: HTTP header (recommended)

```
x-vercel-protection-bypass: {your-generated-secret}
```

## Method 2: Query parameter

For tools that cannot set custom headers (webhook URL verification for Slack, Stripe, etc.):

```
https://your-deployment.vercel.app/api/webhook?x-vercel-protection-bypass=your-generated-secret
```

Use cases: Slack bot webhook URL verification, Stripe webhook endpoints, GitHub webhooks, any third-party service sending POST requests.

## Advanced: browser session bypass cookie

For in-browser testing (Playwright), set additional header:

```
x-vercel-set-bypass-cookie: true
```

This sets authorization bypass as a cookie via redirect with `Set-Cookie` header. Subsequent requests in the browser session are automatically authenticated.

For iframe access: `x-vercel-set-bypass-cookie: samesitenone` (sets `SameSite=None`).

## Playwright configuration example

```typescript
// playwright.config.ts
export default defineConfig({
  use: {
    extraHTTPHeaders: {
      'x-vercel-protection-bypass': process.env.VERCEL_AUTOMATION_BYPASS_SECRET,
      'x-vercel-set-bypass-cookie': 'true',
    },
  },
});
```

## Security note

The bypass secret should be stored as an environment variable, not hardcoded in code or webhook URLs. Many third-party services support environment variable substitution in webhook URLs.
