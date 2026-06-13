# OWASP ZAP — Passive Scanning

**Tool:** OWASP ZAP (zaproxy) · **Type:** DAST · **Concept:** passive scanning

Passive scanning in ZAP inspects HTTP requests and responses that already flow
through its proxy **without sending any new payloads** — it never modifies traffic,
so it is safe to run against any in-scope target. Passive scan rules examine
response headers, bodies, cookies, and HTML/JS to flag issues such as missing
security headers (CSP, HSTS, X-Content-Type-Options), cookies without `HttpOnly`/
`Secure`/`SameSite`, information disclosure (stack traces, server banners, private
IPs), insecure form posts, and weak cache-control. Each finding becomes an **alert**
with a risk and a **confidence** level.

**Why it matters for WebHound:** WebHound's header/CSP/CORS/cookie engines are
passive-equivalent — they reason over captured responses. ZAP's passive-rule
catalogue is a reference for *what to look for without active probing* and for how
to phrase low-noise, evidence-backed findings. Passive rules are high-precision and
low-risk, making them ideal first-pass detectors.

**Related:** [[zap-active-scanning]], [[zap-evidence-model]], [[zap-alert-confidence]].
