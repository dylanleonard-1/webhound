# Static vs Dynamic vs Hybrid Scanning

**Source:** Executive Summary.pdf (planning reference) · **Concept:** static vs dynamic detection

**Static analysis (SAST)** inspects code or page content *without executing it* —
AST/pattern matching (Semgrep, Gitleaks, libinjection). Strengths: very fast, broad
coverage of all code paths, deterministic, offline. Weakness: **high false
positives** and it misses runtime/context issues (dynamic behaviour, config errors)
because it never runs the app.

**Dynamic analysis (DAST)** actively probes the *running* app — sends payloads over
HTTP or via a browser and observes behaviour (ZAP, sqlmap, XSStrike, DalFox).
Strengths: finds **real, exploitable** issues with **far fewer false positives**,
language-independent, tests real config/data flows. Weakness: slower, only tests
paths/payloads it reaches (false negatives), some payloads risk site stability.

**Signature** detection is precise on known patterns but misses novel/obfuscated
attacks; **heuristic/rule** detection (context-aware payloads) balances the two;
**ML** is emerging but needs labelled data and local-only execution for privacy.

**Why it matters for WebHound:** no single approach suffices. Static over-reports;
dynamic confirms but under-covers. WADE must weight findings by method — a static
signal is a *candidate*; a dynamic proof is a *confirmation* — and keep confidence
separate from severity.

**Related:** [[hybrid-engine-architecture]], [[libinjection-classification-model]], [[sqlmap-confidence-model]].
