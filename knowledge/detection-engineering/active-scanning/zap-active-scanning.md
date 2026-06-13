# OWASP ZAP — Active Scanning

**Tool:** OWASP ZAP (zaproxy) · **Type:** DAST · **Concept:** active scanning

Active scanning **sends crafted attack payloads** to the target and inspects the
responses for proof of a vulnerability. ZAP first spiders/crawls to enumerate URLs,
parameters and forms, then its active scan rules inject payloads for XSS, SQL
injection, path traversal, command injection, SSRF, and more. Detection is
**evidence-driven**: e.g. an SQLi rule may inject a boolean or time-based payload
and confirm the flaw only when the response differs as predicted; an XSS rule
reflects a unique marker and checks it appears un-encoded in an executable context.
ZAP can also run custom scripts (JavaScript/Zest) to reach edge cases.

Because active scanning is intrusive, it must only run against **authorised,
in-scope** targets — it can change state and stress a site. Its strength is finding
*real, exploitable* issues with low false positives; its weakness is breadth (it
only tests what it discovered and has payloads for).

**Related:** [[zap-passive-scanning]], [[zap-scanner-rule-architecture]], [[static-vs-dynamic-comparison]].
