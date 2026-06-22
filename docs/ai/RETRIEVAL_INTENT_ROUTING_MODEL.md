# Retrieval Intent Routing Model — Phase CONTROL-2G

Fixes the CONTROL-2F bug: prose IMPLEMENTATION questions ("where is WADE
implemented", "what handles threat intelligence") now route to CODE, while prose
KNOWLEDGE questions ("how does HSTS prevent downgrade", "what does CSP help
prevent") still route to DOCS. Deterministic — no LLM, no cloud, no chunk changes.

## Intent types
| Intent | Wants | Detection |
|--------|-------|-----------|
| **CODE_LOOKUP** | implementation / file / module / class / route / engine / handler / source | code-location phrase OR symbol-like query, and NO knowledge phrase |
| **KNOWLEDGE_EXPLANATION** | concept / best-practice / impact / prevention / remediation / standard | knowledge phrase, and NO code signal |
| **MIXED** | both | BOTH a code-location phrase AND a knowledge phrase |
| **UNKNOWN** | — | neither → existing CONTROL-2E hybrid behavior |

## Deterministic detection (`classify_intent`)
- **Code phrases:** `where is/are/does`, `where do we`, `what handles`, `what/which module`, `which file/class/function`, `show code`, `source code`, `implemented`, `implementation`, `located`, `defined`, `lives`, `performs` — plus the CONTROL-2E `_is_symbol_like_query` (snake_case/CamelCase/path/short noun phrase).
- **Knowledge phrases:** `how does/do/should`, `why does/is`, `what does/is`, `explain`, `best practice`, `prevent`, `mitigate`, `remediate`, `guidance`, `impact`, `risk`, `standard`, `cause`, `help`, `protect`.
- BOTH present → MIXED. Examples (generalized, not special-cased):
  `where is WADE implemented` → CODE_LOOKUP · `what handles threat intelligence` → CODE_LOOKUP ·
  `how does HSTS prevent downgrade attacks` → KNOWLEDGE · `where is HSTS handled and why does it matter` → MIXED.

## Intent-specific ranking (`_intent_bonus`)
- **CODE_LOOKUP** → prefer code: `symbol_boost` + **path-overlap** (code whose file path contains the query's topical tokens, e.g. `threat intelligence` → `.../threat_intel/...`) + source-tier `(8-tier)·0.04` (production > api > wade > tests); **docs demoted −0.15**; tests stay below production.
- **KNOWLEDGE_EXPLANATION** → prefer docs/knowledge `+0.10`, **tests −0.30**, NO code-symbol boost.
- **MIXED** → balanced (half code boost + half path-overlap; docs `+0.04`; tests `−0.15`) **plus a top-5 coverage guarantee**: if the top-5 lacks a code or a doc source, the best available of the missing type is swapped into the last slot.
- **UNKNOWN** → unchanged CONTROL-2E hybrid.

Path-overlap excludes generic structural tokens (`api`, `app`, `web`, `src`, `lib`,
`scanner`, `webhound`, …) so it matches *topical* path segments, not boilerplate.

## Guarantees
- CONTROL-2E knowledge-query guard preserved: the 5 prose doc guards still rank docs #1.
- CONTROL-2D/2E code traceability preserved: the 10 symbol concepts still PASS 10/10.
- Boosts are additive/metadata-driven; the dense-quality-gate (≥8/10) is unaffected.
