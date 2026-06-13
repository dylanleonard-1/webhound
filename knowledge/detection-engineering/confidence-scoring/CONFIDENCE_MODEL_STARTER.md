# Confidence Model (starter)

A shared vocabulary for how sure WebHound is that a finding is real. Confidence is
**separate** from severity (how bad it would be if real).

## Bands
| Confidence | Meaning | Typical basis |
|-----------|---------|---------------|
| **~0.95** | Almost certainly real | direct runtime proof / unambiguous evidence + corroboration |
| **~0.75** | Likely real | strong evidence, minor ambiguity |
| **~0.50** | Needs review | mixed/weak signals; human or further evidence needed |
| **~0.25** | Weak signal | single static heuristic; correlation-only, not standalone |

## Inputs to confidence
- **Source authority** — Tier A/B evidence raises confidence; Tier D/E lowers it.
- **Runtime proof** — observed dynamic behavior > static pattern.
- **Corroboration** — multiple independent signals agree (behavior + context +
  provenance + threat-intel).
- **FP history** — a finding type with a known FP lesson (see the FP catalog)
  starts lower until corroborated.

## Rules
- A single weak static signal (e.g. entropy 5.53) is **~0.25 and correlation-only**
  — never a standalone finding.
- Correlation confidence must derive from constituents (with a floor, e.g. ≥0.6),
  not be hard-coded.
- Confidence + severity + evidence + remediation are all required on every finding.

**Review status:** curated (seeded). **Authority:** internal methodology + audit
docs.
