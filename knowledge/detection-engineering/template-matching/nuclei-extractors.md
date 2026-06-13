# Nuclei Templates — Extractors

**Tool:** Nuclei / nuclei-templates · **Concept:** extractors / evidence capture

Where matchers decide *if* something is found, **extractors** pull the **evidence
and data** out of the response. Types: `regex` (capture groups), `kval`
(key/value from headers or cookies), `json` (JQ-like over JSON bodies), `xpath`, and
`dsl`. Extracted values can be displayed as the finding's evidence, fed into later
requests (dynamic multi-step templates), or used to report exact versions,
identifiers, or leaked data. `internal: true` extractors pass data between steps
without printing it.

**Why it matters for WebHound:** extractors are the template equivalent of ZAP's
evidence string — they make a finding **explainable and verifiable** by capturing
the precise proof (the leaked version, the reflected token, the error text). This
reinforces the rule that every WebHound detector should emit an evidence locator,
and shows how to chain extracted context into follow-up checks (useful for
correlation and multi-step detection).

**Related:** [[nuclei-matchers]], [[zap-evidence-model]], [[nuclei-template-structure]].
