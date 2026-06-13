# Azure Front Door and WAF

**Provider:** Microsoft Azure · **Authority:** Tier A official docs · **Source:** https://learn.microsoft.com/en-us/azure/frontdoor/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Azure Front Door is

Azure Front Door is Microsoft's global CDN and load balancer with integrated WAF. Used by
enterprises hosting on Azure. Equivalent to CloudFront+WAF (AWS) or Cloudflare (CDN).

## WAF rule sets

Azure WAF on Front Door includes:
- **OWASP Core Rule Set (CRS)**: 3.1, 3.2 (OWASP-recommended rules for SQLi, XSS, RCE, LFI)
- **Microsoft Default Rule Set (DRS)**: Microsoft's managed rule set, updated more frequently than CRS
- **Bot protection rule set**: blocks known bots, protects from automated attacks

## Response indicators for blocked requests

When Azure WAF blocks a request:
- Default: 403 Forbidden
- `x-azure-ref` header present on all Azure Front Door responses (trace ID)
- Body may contain Azure branding or custom operator page
- Custom block pages configurable by operator

Example response:
```
HTTP/1.1 403 Forbidden
x-azure-ref: 0abc123...
Content-Type: text/html
```

## Bot protection

Azure's bot protection rule set:
- Blocks known malicious bots (IP reputation)
- Challenges unknown/suspicious bots
- Allowlists known good bots (search engines)

Scanner traffic may be categorized as "unknown bot" and challenged.

## Geo-filtering

Azure Front Door WAF supports geo-filtering:
- Block or allow by country/region
- Custom response for blocked geos (default: 403)

## Response headers from Azure Front Door

| Header | Notes |
|---|---|
| `x-azure-ref` | Trace ID — unique per request (always present) |
| `x-fd-healthprobe` | Present on Azure Front Door health probe requests |
| `x-ms-ref` | Alternate form on some configs |

## Identifying Azure Front Door

- `x-azure-ref` header in response
- IP resolving to Azure Front Door edge (Azure AS8075)
- Custom domain certificate issued by Microsoft (seen in TLS handshake)
- `via: 1.1 Azure` in some configs

## Scanner allowlisting

Azure WAF exclusion lists:
- WAF Policy → Exclusions → add condition (request header/cookie/query param matching)
- IP allowlist: WAF Custom Rule → match IP → ALLOW action (priority above WAF rules)

**Related:** [[aws-waf-detection]], [[cloudflare-waf-detection]].
