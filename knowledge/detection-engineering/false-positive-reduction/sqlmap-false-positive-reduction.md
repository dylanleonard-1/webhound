# sqlmap — False-Positive Reduction

**Tool:** sqlmap · **Concept:** false-positive reduction

sqlmap suppresses false positives with several guards: it **repeats** tests and
requires stable, repeatable differentials; it sends **control/negation** payloads
and only reports when the positive and negative cases diverge as predicted; for
time-based it verifies the delay **scales** with the requested sleep rather than
matching one noisy slow response; it accounts for **dynamic page content** (CSRF
tokens, timestamps, rotating ads) by comparing against a baseline so normal page
variance is not mistaken for injection; and it detects WAFs to avoid
mis-reading blocked responses as vulnerabilities.

**Why it matters for WebHound:** these are reusable anti-FP techniques for any
active detector — **baseline comparison, controlled negation, reproducibility, and
delay-scaling verification**. They map directly onto WebHound's false-positive
catalog and WADE's confidence logic: a finding that survives repetition and a
negative control deserves higher confidence; one that does not should be downgraded
with the reason recorded.

**Related:** [[sqlmap-confidence-model]], [[dalfox-false-positive-reduction]], [[scanner-audit-recommendations]].
