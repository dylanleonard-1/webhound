# OWASP ZAP — Evidence Model

**Tool:** OWASP ZAP (zaproxy) · **Concept:** evidence collection

Every ZAP alert carries structured **evidence** so a finding can be verified and
explained, not just asserted. An alert records: the **URL** and **parameter**, the
**attack** payload sent, the **evidence** string (the exact substring in the
response that proves the issue), the **method**, CWE/WASC identifiers, a risk
rating, a confidence level, and a human description with remediation. The evidence
string is the linchpin — it points to *where* in the response the proof lives (e.g.
the reflected script tag, the SQL error text, the missing header).

**Why it matters for WebHound:** WebHound's manifest/finding model already stores
source pointers and evidence snippets. ZAP's alert schema is a mature reference for
**what minimum evidence every detector should emit** so WADE can later cite *why*
a finding is real, map it to CWE/OWASP, and judge confidence. A detector that cannot
produce an evidence locator should be treated as low-confidence.

**Related:** [[zap-alert-confidence]], [[zap-passive-scanning]], [[scanner-audit-recommendations]].
