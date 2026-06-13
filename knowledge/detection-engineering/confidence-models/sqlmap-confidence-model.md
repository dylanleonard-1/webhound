# sqlmap — Confidence Model

**Tool:** sqlmap · **Concept:** confidence scoring / dynamic proof

sqlmap's confidence is **empirical**: a parameter is reported injectable only after
the technique's prediction is reproduced. Boolean-based requires the TRUE payload
and FALSE payload to yield consistent, distinguishable responses across repeated
requests; time-based requires the induced delay to track the requested sleep value
(and not random latency); error-based requires the DBMS error to actually surface.
sqlmap raises `--level` (more injection points: headers, cookies) and `--risk`
(heavier payloads) to trade coverage for intrusiveness, and repeats tests to defeat
flaky responses.

**Why it matters for WebHound:** this is the **"dynamic proof requirement"** in
practice — confidence comes from a *reproducible, controlled differential*, not from
a single suspicious response. WADE should treat findings that meet a reproducible
proof bar as high-confidence and demand evidence of the differential; one-shot
heuristic matches are low-confidence by comparison.

**Related:** [[sqlmap-detection-overview]], [[zap-alert-confidence]], [[sqlmap-false-positive-reduction]].
