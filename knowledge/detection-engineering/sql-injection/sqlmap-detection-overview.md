# sqlmap — SQL Injection Detection Overview

**Tool:** sqlmap · **Type:** DAST · **Concept:** SQL injection detection

sqlmap is the reference automated **SQL injection** detector and exploiter. For each
injectable parameter it tests the five canonical SQLi techniques: **boolean-based
blind**, **error-based**, **UNION query-based**, **stacked queries**, and
**time-based blind** (and inline/out-of-band variants). Detection is **differential
and proof-driven**: sqlmap sends a payload plus control requests and confirms
injection only when responses change as predicted — e.g. a `TRUE` vs `FALSE`
condition produces stable, repeatable page differences, or a `SLEEP()` payload
reproducibly delays the response. This requirement for a *verifiable response
difference* is what keeps false positives low.

**Why it matters for WebHound:** SQLi is dynamic by nature — static page inspection
cannot confirm it. sqlmap's technique taxonomy and its "confirm with a controlled
differential" methodology are the gold standard WebHound's SQLi-relevant detectors
and WADE confidence model should reference, and the benchmark to compare a future
active SQLi engine against.

**Related:** [[sqlmap-fingerprinting]], [[sqlmap-confidence-model]], [[sqlmap-false-positive-reduction]], [[libinjection-classification-model]].
