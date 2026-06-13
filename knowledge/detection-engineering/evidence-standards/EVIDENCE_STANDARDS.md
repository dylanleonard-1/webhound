# Evidence Standards (Standard of Proof)

The bar a finding must clear before WebHound reports it. Grounded in
`WEBHOUND_DETECTION_AUDIT.md`'s standard of proof: *"keyword exists ≠ malware ·
/admin exists ≠ exposed admin · form defaults to GET ≠ credential leak · header
absent ≠ exploitable."*

## Rules
1. **Keywords alone are insufficient.** A scary substring in copy/RSC/text is not
   malware. Require executable context + behavior.
2. **A status code alone is insufficient.** A 200 (SPA shell) at `/admin` is not an
   exposed admin panel; a 404 is not proof of absence.
3. **Distinguish static vs dynamic evidence.** Static signals (entropy, string
   patterns) are weak on their own; dynamic behavior (network beacon, credential/
   cookie access, redirect) is stronger. Prefer corroboration.
4. **Framework transport scripts ≠ executable user JS without context.** Next.js
   RSC / `_next/data` / prefetch traffic is framework plumbing, not application API
   or attacker code — label it distinctly.
5. **Severity follows impact + exploitability**, not mere presence. A common config
   weakness (e.g. CSP `unsafe-inline` without nonces) is MEDIUM, not HIGH.
6. **Correlation requires a relationship, not co-occurrence.** Two findings on a
   page is not a "threat chain" unless there is a real attack path linking them on
   the same page/host, each constituent clearing a confidence floor.
7. **Every finding needs evidence + confidence + remediation.** No finding without
   what was observed, how sure we are, and what to do.
8. **Downgrades / suppressions record reason + source.** When a finding is lowered
   or suppressed, log *why* and the source (audit lesson, FP rule, threat-intel) for
   auditability. (Phase 8 enrichment is suggest-only — it never auto-suppresses.)

## Anti-patterns (from the FP catalog)
Per-page duplication inflating counts; over-severity on public/non-credentialed
resources; counting social links as APIs; entropy-only malware claims; query-variant
node inflation. See `knowledge/false-positive-catalog/`.

**Review status:** curated (seeded). **Authority:** internal methodology + audit
docs + Tier-A standards.
