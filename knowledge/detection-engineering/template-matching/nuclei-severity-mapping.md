# Nuclei Templates — Severity Mapping

**Tool:** Nuclei / nuclei-templates · **Concept:** severity mapping / classification

Every template's `info` block declares a **severity** (`info`, `low`, `medium`,
`high`, `critical`) and a **classification**: `cwe-id`, optional `cve-id`,
`cvss-metrics`/`cvss-score`, and `tags`. Severity is a property of the *issue class*
(set by the template author against CVSS/impact), independent of the runtime
confidence that a given match is real. Tags (e.g. `sqli`, `xss`, `cve`, `exposure`,
`tech`) drive selection and grouping.

**Why it matters for WebHound:** Nuclei demonstrates the discipline of **mapping each
detection to CWE/CVE/CVSS up front**, and of keeping *severity* (impact of the class)
separate from *confidence* (certainty of this instance). WADE's severity
recommendation should lean on standardised CWE/CVSS mappings like these, while its
confidence comes from the evidence/matcher strength — never conflating the two. This
mapping is also the join key for WebHound's OWASP/MDN/CWE knowledge.

**Related:** [[nuclei-template-structure]], [[zap-alert-confidence]], [[scanner-audit-recommendations]].
