# Static vs Dynamic vs Hybrid Scanning

**Source:** Executive Summary.pdf (planning reference, binary not committed) · **Concept:** static vs dynamic detection

Derived from full-text extract of the planning PDF. Binary intentionally not committed.

## SAST — Static Analysis

Analyzes code or page content *without executing it* — AST/regex/pattern matching.
Representative tools: Semgrep (code-aware grep patterns, community rules for SQLi/XSS/
CSRF, offline, fast, broad language support), Gitleaks (regex + entropy secret scanning),
libinjection (C library — SQL/SQLi token parsing; parse an HTTP parameter and identify
if it looks like SQLi; fast building-block pre-filter).

**Pros:** very fast, broad code-path coverage (all paths, not just exercised ones),
deterministic, fully offline.
**Cons:** high false positives (no runtime context), misses runtime/config issues,
language-specific parsers required.

## DAST — Dynamic Analysis

Actively probes a running app — sends payloads over HTTP or via a browser, observes
responses. Representative tools: ZAP (full DAST, active+passive), sqlmap (SQLi
differential proof), XSStrike (context-tailored XSS payloads), DalFox (verified XSS).

**Pros:** finds real, *exploitable* issues; **far fewer false positives than static
tools** (exact PDF quote); language-independent; tests real config and data flows.
**Cons:** slower; only tests paths and payloads it reaches (FN risk); payloads can
risk target stability; black-box (cannot see all code paths).

Key principle: "Dynamic scanners generate far fewer false positives than static tools."

## Hybrid

Combines static rule checks + dynamic probes (template scanners + headless browsers).
Static narrows candidates; dynamic confirms. Lower combined FP/FN.
**Cons:** more complex; requires tool coordination and tuning.

## Signature-Based

Match against known bad patterns/blacklists (Gitleaks regex, Yara rules).
Precise for known threats; low CPU cost. Misses novel/obfuscated; needs constant
updates as threats evolve.

## Heuristic / Rule-Based

Generalized rules: unsanitized output, use of eval(), high JS entropy, missing CSRF
tokens. Catches new variants if the rule class covers them. Requires tuning to avoid
over-firing.

## ML-Based

Train classifiers on benign vs malicious samples; detect unseen obfuscation patterns.
Needs labeled data, heavy compute. Very limited open-source options for web security.
**All ML ops must run locally — never send internal site data to external cloud APIs.**

## Sandbox / Runtime Instrumentation

Execute JS instrumented (hook function calls, monitor network/DOM mutations). Catches
skimmer scripts making exfil network calls or injecting DOM changes at runtime.
Complex to set up; performance overhead; best for third-party asset monitoring.

## FP/FN Tradeoffs Summary

| Method | FP rate | FN rate | Notes |
|---|---|---|---|
| Static/SAST | High | Low (broad path coverage) | Over-reports, misses runtime |
| Dynamic/DAST | Low | Medium (path-dependent) | Requires probe coverage |
| Signature | Very low for known | High for novel | Fails on obfuscation |
| Heuristic | Medium | Medium | Needs tuning |
| ML | Low (if trained well) | Low (if trained well) | Needs labeled data |
| Sandbox | Low | Low | High complexity/overhead |

## Why this matters for WebHound

No single approach suffices. WADE must weight findings by method:
- A **static signal** = candidate (needs confirmation)
- A **dynamic proof** = confirmation (reproducible differential)
- Confidence and severity must stay on separate axes (reference: ZAP alert model)

**Related:** [[hybrid-engine-architecture]], [[libinjection-classification-model]], [[sqlmap-confidence-model]], [[zap-alert-confidence]].
