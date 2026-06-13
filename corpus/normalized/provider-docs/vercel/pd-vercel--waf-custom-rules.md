# Vercel WAF Custom Rules

Source: https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Actions available per rule

- **log** — records request; rule execution continues (useful for testing rule conditions)
- **deny** — blocks request; returns 403
- **challenge** — serves JS challenge; non-browser clients fail
- **bypass** — exempts traffic from other rules (use for allowlisting scanners/CIs)
- **redirect** — redirects to specified URL
- **rate limit** — requires follow-up action (log/deny/challenge/429)

## Persistent actions

When a rule with Challenge or Deny fires, optionally block source IP for a time period (1 min to extended window). Stored at platform-firewall level so future requests are blocked before CDN processing — doesn't count against CDN quota.

Available on: Challenge, Deny, Rate Limit actions.

## Rule execution order

1. Custom rules (per project, in user-configured precedence order)
2. WAF Managed Rulesets

Rules stop on first Deny or Challenge match. Log rules continue through.

## vercel.json configuration format

WAF rules can be declared in `vercel.json` under `routes` with `mitigate` property:

```json
{
  "routes": [
    {
      "src": "/(.*)",
      "has": [{"type": "header", "key": "x-react-router-prerender-data"}],
      "mitigate": {"action": "deny"}
    }
  ]
}
```

Actions in `vercel.json`: `challenge` and `deny` only (log/bypass/redirect NOT supported here).
`has`/`missing` conditions match headers, cookies, query params, host.

## Natural language rule examples (scanner relevance)

| Pattern | Rule created |
|---|---|
| "Block paths ending in .env, .git, .bak" | Deny rule with OR path-suffix conditions |
| "Challenge requests where user-agent contains curl or wget" | Challenge rule with OR user-agent conditions |
| "Rate limit POST /auth/login to 10 per min per IP, deny 15 min" | Rate limit + persistent deny action |
| "Block requests from outside North America on /api/admin" | Deny rule with continent condition |

## Bypass rule for scanner allowlisting

To allowlist a specific scanner/CI user agent blocked by Bot Protection Managed Ruleset:
1. Create Custom Rule with action = **bypass**
2. Condition: User-Agent equals exact scanner UA string
3. Place bypass rule ABOVE any deny/challenge rules in precedence

Alternatively use `x-vercel-protection-bypass` header to skip all firewall+bot checks.

## Scanner detection signatures

If a Vercel site returns:
- HTTP 403 with minimal JSON/HTML body + `x-vercel-id` header → custom Deny rule or OWASP
- JS challenge page ("Vercel Security Checkpoint") → Challenge rule or Bot Protection Ruleset
- HTTP 429 → Rate limit rule triggered
- HTTP 302 with `x-vercel-id` present → Redirect rule
