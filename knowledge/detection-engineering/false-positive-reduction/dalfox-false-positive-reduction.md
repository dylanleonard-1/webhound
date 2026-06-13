# DalFox — False-Positive Reduction

**Tool:** DalFox · **Concept:** false-positive reduction

DalFox keeps XSS false positives low by **verifying execution rather than
reflection**. A reflected marker alone is not reported; DalFox checks how the marker
is parsed in the DOM/HTML context and, in verify mode, confirms the payload actually
executes in a headless browser before flagging it. It is WAF-aware (a blocked
response is not a vulnerability), deduplicates findings per parameter/context, and
its structured output records the proving evidence so a human can re-check.

**Why it matters for WebHound:** "**reflection ≠ vulnerability**" is one of the most
common XSS false-positive sources, and WebHound's false-positive catalog should
encode it explicitly. DalFox's discipline — confirm the parsed context and, ideally,
runtime execution before reporting — is the anti-FP pattern WADE should require for
XSS-class findings, downgrading any XSS finding that lacks execution/context proof
and recording the reason.

**Related:** [[dalfox-xss-validation]], [[sqlmap-false-positive-reduction]], [[zap-alert-confidence]].
