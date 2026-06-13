# OWASP ZAP — Scanner Rule Architecture

**Tool:** OWASP ZAP (zaproxy) · **Concept:** scanner rule architecture

ZAP's detection logic is organised as **independent scan rules** packaged in
add-ons, split into **passive** rules (observe traffic) and **active** rules (inject
payloads). Each rule is self-contained: it declares the vulnerability it targets,
the payloads/checks it runs, the evidence it extracts, and its CWE/WASC mapping and
default risk/confidence. Rules are versioned and distributed via the ZAP
Marketplace, so the detection catalogue evolves without changing the core engine.
A scan policy enables/tunes rules and sets thresholds and attack strength.

**Why it matters for WebHound:** this **plugin-per-detection** architecture is the
model WebHound's engines already echo (one engine per concern). The lessons for the
Phase-9 audit: every detector should declare its target vuln, payloads/checks,
evidence locator, CWE/OWASP mapping, and default risk+confidence; detection content
should be data-driven and independently testable; and scan strength/scope must be
configurable so intrusive checks are opt-in.

**Related:** [[zap-active-scanning]], [[nuclei-template-structure]], [[hybrid-engine-architecture]].
