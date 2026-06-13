# Vercel WAF Managed Rulesets

Source: https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Available managed rulesets

1. **OWASP Core Ruleset** — predefined rules based on OWASP Top Ten (requires Pro/Enterprise)
2. **Bot Protection Managed Ruleset** — detects and challenges/blocks unwanted bots
3. **AI Bots Managed Ruleset** — detects and logs/blocks AI crawler bots

## OWASP Core Ruleset

Based on OWASP Top Ten attack categories. Each rule can be set to:
- **Log** — detect and record without blocking (recommended first: monitor live traffic)
- **Deny** — block matching requests with 403

Attack categories covered: SQLi, XSS, path traversal, command injection, RFI/LFI, protocol violations, scanner detection signatures.

Granular enable/disable per rule category. Changes apply immediately without redeployment.

## Bot Protection Managed Ruleset

Action options:
- **Log** — visibility only; records bot traffic
- **Challenge** — serves JS challenge to traffic unlikely to be a browser

Scanner implication: automated HTTP clients (curl, Python requests, Go net/http) cannot pass JS challenge — they will hang or receive an HTML challenge page with no useful response body.

## AI Bots Managed Ruleset

Action options:
- **Log** — monitor AI crawler traffic
- **Deny** — block all AI bot traffic (GPTBot, Claude-Web, etc.)

## Bypassing managed rulesets

Method 1: Custom Rule with bypass action + condition matching target traffic (place BEFORE managed ruleset in execution order — custom rules run first).

Method 2: `x-vercel-protection-bypass` header with valid bypass secret (bypasses Firewall blocks + Bot Protection; does NOT bypass active DDoS IP blocks).

## Rule execution order

```
Custom rules (user order) → WAF Managed Rulesets
```

Bypass custom rule must be ordered ABOVE any blocking custom rule to take precedence.

## Scanner detection context

If a WebHound scan target shows:
- `server: Vercel` header + JS challenge page → Bot Protection Managed Ruleset active
- 403 with OWASP pattern in response → OWASP ruleset blocking scanner payload
- AI bot user-agent denial → AI Bots ruleset active

To confirm OWASP coverage: send test payloads (SQLi, XSS markers) and observe if 403 response appears vs baseline.
