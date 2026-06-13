# Scanner Audit Recommendations (Phase-9 Prep)

**Source:** Executive Summary.pdf + Master Tooling/WADE Roadmap (planning references) · **Concept:** future scanner audit guidance

Detection knowledge from Phase 6C feeds the **Phase-9 full engine audit**. For every
WebHound engine (Recon, DNS, TLS, Headers, CSP, CORS, Cookies, Crawler, Forms,
Sensitive Paths, JavaScript, Third-Party Domains, CMS, API Discovery, Threat Intel,
Compromise, Correlation, Reporting, WADE), audit against this checklist drawn from how
the reference tools detect:

- **Evidence:** does the detector emit an evidence locator (à la ZAP alert / Nuclei
  extractor)? No evidence ⇒ low confidence.
- **Proof bar:** for active-class findings, is there a *reproducible differential*
  (sqlmap) or *verified execution/context* (DalFox/XSStrike)? Reflection or a single
  suspicious response is not proof.
- **Confidence vs severity:** kept on separate axes (ZAP); severity from CWE/CVSS
  mapping (Nuclei), confidence from evidence strength.
- **False-positive guards:** baseline comparison, negative controls, dedup,
  WAF-awareness, delay-scaling.
- **Coverage/recall:** input discovery (parameter mining) so detectors aren't blind
  to untested inputs.
- **Mapping & tests:** each finding mapped to CWE/OWASP and covered by a regression
  test; gaps documented.

**Sequence:** Review → Fix → Test → Regression-protect → *then* benchmark (Phase 10).

**Related:** [[repo-priority-summary]], [[zap-evidence-model]], [[sqlmap-false-positive-reduction]], [[nuclei-severity-mapping]].
