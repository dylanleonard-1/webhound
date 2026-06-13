# Akamai Bot Manager and WAF

**Provider:** Akamai · **Authority:** Tier A summary (direct access blocked 403; authored from official docs knowledge) · **Source:** https://techdocs.akamai.com/
**Terms note:** Authored detection-relevant summary; not a verbatim mirror.

## What Akamai is

Akamai is a major CDN and security platform used by large enterprises. Products relevant
to scanning:
- **Kona Site Defender (KSD)**: WAF with managed rules (OWASP + Akamai rules)
- **Bot Manager**: bot detection and mitigation
- **App & API Protector**: unified WAF + bot + DDoS
- **Akamai SIEM**: event feeds for security operations

## Bot Manager detection mechanisms

Bot Manager is Akamai's primary anti-automation layer. Detection signals:

| Signal | How it works |
|---|---|
| **Browser telemetry** | JavaScript challenge harvests browser attributes (canvas fingerprint, WebGL, fonts, plugins) |
| **Behavioral biometrics** | Mouse movement, scroll pattern, click timing |
| **TLS fingerprinting** | JA3/JA3S — scanner stack fingerprint differs from browsers |
| **HTTP/2 SETTINGS** | Browser-specific frame ordering checked |
| **IP reputation** | Akamai threat intelligence — scanner datacenter IPs often flagged |
| **Sensor data cookie** | `_abck` cookie contains encrypted telemetry; must be valid for subsequent requests |

## `_abck` cookie (Bot Manager v1 / Moto)

- Set by Akamai's JavaScript challenge on first page load
- Contains encrypted telemetry payload validated server-side
- Subsequent requests without valid `_abck` → 403 or redirect
- Cookie value is not reproducible without executing Akamai's JS challenge code
- Scanner automated fetch without JS execution → missing or invalid `_abck` → blocked

## Response indicators for blocked requests

- HTTP 403 Forbidden with Akamai reference number in body (e.g., `Reference #12.xxx`)
- `x-check-cacheable: NO` header
- Redirect to `akam-rt.com/web-login` on JS challenge
- HTML body containing `akamai` or `akamai reference` text

## WAF (Kona Site Defender)

- Rules delivered as Akamai security configs (pushed via Property Manager API)
- Triggers on common attack patterns: SQLi, XSS, OS command injection, RFI
- Custom rules configurable by operator
- Block action: 403 with Akamai reference ID

## Scanner allowlisting for Akamai

Official method:
- Whitelist scanner IPs in Akamai Bot Manager → allow list
- Akamai Control Center → Security → Bot Manager → Manage client lists
- Alternatively: custom rule to pass requests with specific header value (operator-configured)

Akamai API: `PUT /appsec/v1/configs/{configId}/custom-deny` or exception list API.

## Identifying Akamai-fronted sites

- `x-akamai-session-info` header (on some configs)
- `akamaierror` cookie on blocks
- `server: AkamaiGHost` or `AkamaiNetStorage`
- PTR record of IP resolving to `akamai.net` or `edgesuite.net`
- IP in Akamai ASN (AS20940, AS16625)

**Related:** [[fastly-waf-and-bot-detection]], [[sucuri-waf]].
