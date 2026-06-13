# Google Cloud Armor Security Policies

**Provider:** Google Cloud · **Authority:** Tier A official docs · **Source:** https://cloud.google.com/armor/docs/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Google Cloud Armor is

Google Cloud Armor is GCP's WAF and DDoS protection service for:
- External HTTP(S) Load Balancers
- TCP/SSL Proxy Load Balancers
- Global external Application Load Balancers

## Security policy rules

Cloud Armor uses priority-based rules:
- **Preconfigured rules** (WAF): OWASP ModSecurity Core Rule Set (CRS 3.3)
  - SQLi: `sqli-stable` rule group
  - XSS: `xss-stable` rule group
  - RFI/LFI: `lfi-stable`, `rfi-stable`
  - RCE: `rce-stable`
- **Custom rules**: CEL (Common Expression Language) expressions matching request attributes
- **Adaptive Protection**: ML-based DDoS detection (auto-generates rules during attacks)

## Response indicators for blocked requests

Cloud Armor blocked requests return:
- Default: 403 with HTML body containing minimal error
- Custom deny: configurable status code (400-599) + custom body
- No distinctive header that uniquely identifies Cloud Armor (uses standard GCP load balancer headers)

GCP load balancer headers on passing requests:
- `via: 1.1 google`
- `server: Google Frontend` (on some configs)
- No `cf-ray`-style unique block identifier

## reCAPTCHA Enterprise integration

Cloud Armor integrates with reCAPTCHA Enterprise for bot challenges:
- CAPTCHA action creates assessment, challenges suspicious traffic
- `recaptcha-ca-token` cookie set after passing challenge
- Bot detection based on reCAPTCHA score (0.0 = bot, 1.0 = human)

## Rate limiting

Cloud Armor supports rate limiting rules:
- `RATE_BASED_BAN`: ban IP after threshold exceeded
- `THROTTLE`: reduce request rate (return 429)
- Per-IP or per-region rate limits
- Scanner exceeding threshold → 429 or temporary IP ban

## Identifying Google Cloud Armor / GCP LB

- `via: 1.1 google` header
- `server: Google Frontend` (some configs)
- IP resolving to Google GOOG ASN (AS15169)
- GCP load balancer health check user-agent in logs: `GoogleHC/1.0`

## Scanner allowlisting

Cloud Armor allowlist approach:
- Add scanner IP to security policy rule: `origin.ip == "x.x.x.x"` → allow
- Or create IP match condition with ALLOW action at high priority
- API: `gcloud compute security-policies rules update {priority} --security-policy {name} --src-ip-ranges {CIDR} --action allow`

**Related:** [[aws-waf-detection]], [[cloudflare-waf-detection]].
