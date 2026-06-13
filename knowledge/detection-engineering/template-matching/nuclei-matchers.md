# Nuclei Templates — Matchers

**Tool:** Nuclei / nuclei-templates · **Concept:** matchers / response matching

**Matchers** are how a Nuclei template decides a response proves the issue. Types:
`word` (substring present, with `part: body|header|all`), `regex`, `status` (HTTP
code), `size`, `binary`, and `dsl` (expression language over response fields, e.g.
`duration>=6` for time-based, `contains(body,'x')`, `len(body)`). Matchers combine
via `matchers-condition: and|or`, can be `negative`, and `internal` matchers gate
multi-step logic. Good templates require a **specific, low-false-positive** signal —
a unique error string, a reflected nonce, or a measured time delay — rather than a
generic keyword, mirroring how Nuclei "simulates real steps to reduce false
positives."

**Why it matters for WebHound:** matchers are the formal vocabulary of *proof*. They
map directly to WADE's evidence/confidence model: a `dsl` time-delay or a unique-
marker `word` match is strong proof; a broad `regex` is weak. Auditing a WebHound
detector means asking *"what is its matcher, and is that matcher specific enough to
be high-confidence?"*

**Related:** [[nuclei-extractors]], [[nuclei-template-structure]], [[nuclei-representative-template-patterns]].
