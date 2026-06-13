# Nuclei Templates — Template Structure

**Tool:** Nuclei / nuclei-templates · **Type:** template-driven scanner · **Concept:** template structure

A Nuclei template is a **YAML file that declares a detection as data, not code**. Top
level: an `id`, and `info` metadata (`name`, `author`, `severity`,
`description`, `tags`, and classification such as `cwe-id`, `cve-id`, CVSS). Then a
protocol block (`http`, `dns`, `tcp`, `ssl`, `headless`, …) describing the
**requests** to send (method, path, headers, body, or raw requests, optionally with
`payloads` for fuzzing) and the **matchers**/**extractors** that decide a hit and
pull data out. Templates compose: `matchers-condition: and/or`, multiple requests,
and variables.

**Why it matters for WebHound:** this is the cleanest example of **declarative,
data-driven detection** — the request, the success condition, the severity and the
CWE/CVE mapping all live in one auditable, versioned unit. It is the model for how
WebHound could express detections portably and how the Phase-9 audit can reason
about each engine: *what is sent, what proves a hit, and how is it classified.*

**Related:** [[nuclei-matchers]], [[nuclei-extractors]], [[nuclei-severity-mapping]], [[zap-scanner-rule-architecture]].
