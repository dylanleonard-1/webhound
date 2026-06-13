# OWASP ZAP — Alert Confidence Levels

**Tool:** OWASP ZAP (zaproxy) · **Concept:** confidence model

ZAP separates **risk** (how bad: Informational/Low/Medium/High) from **confidence**
(how sure: False Positive/Low/Medium/High/Confirmed). Confidence reflects how
strongly the evidence supports the finding: a reflected-marker XSS that ZAP did not
execute is lower confidence than one verified in a browser; a header check is
high-confidence because the evidence is unambiguous. This two-axis model lets
analysts triage by *certainty* independently of *severity*.

**Why it matters for WebHound:** this is the canonical pattern for WADE — **keep
confidence and severity as separate axes**. A high-severity finding with low
confidence should not be auto-suppressed nor auto-escalated; it should be surfaced
with its evidence and uncertainty. WebHound's confidence framework should map
detector evidence strength onto a ZAP-like scale and record *why* a confidence was
assigned.

**Related:** [[zap-evidence-model]], [[sqlmap-confidence-model]], [[dalfox-false-positive-reduction]].
