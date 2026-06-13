# Nuclei Templates — Representative Template Patterns

**Tool:** Nuclei / nuclei-templates · **Concept:** reusable detection patterns (sampled)

Across the template corpus a few **reusable detection patterns** recur (these are the
patterns WebHound samples, not the raw payload corpus):

- **Exposure / misconfig:** GET a known path, `word`-match a signature string in the
  body + `status: 200` → e.g. exposed `.git/config`, `.env`, actuator endpoints.
- **Technology/version fingerprint:** match a header (`kval`) or body banner, then
  an `extractor` pulls the version → feeds severity only if a vulnerable range.
- **Reflected injection (SQLi/XSS):** send a unique payload, match a unique error or
  reflected marker; **time-based** uses a `dsl` `duration>=N` matcher for blind SQLi.
- **CVE checks:** version match or a benign proof request, classified with `cve-id`
  and `cvss`.
- **Multi-step:** an internal extractor passes a token/CSRF from request 1 into
  request 2.

**Sampling rule:** WebHound ingests *template structure and a handful of
representative, benign examples* for methodology — never bulk exploit/payload dumps.

**Related:** [[nuclei-matchers]], [[nuclei-extractors]], [[nuclei-severity-mapping]].
