# FP: React/SPA form with no `method`/`action` flagged as a GET password leak

- **Engine area:** forms (`scanner/webhound/engines/forms/`).
- **Original bad behavior:** a React/SPA `<form>` that omits `method`/`action` (HTML
  defaults to `GET`) and contains a password field was flagged as a **credentials-
  over-GET / password-in-URL leak**.
- **Why it was a false positive:** in a React/SPA, submission is handled by
  JavaScript (`onSubmit` → `fetch`/XHR); the form **never does a native GET
  navigation**, so no credentials end up in a URL/query string. "Form defaults to
  GET" ≠ "credentials leak" when JS intercepts submission.
- **Correct behavior:** before flagging, check for JS-handled submission (an
  `onSubmit` handler / framework form / no real native GET to a credential
  endpoint). Only flag a genuine native `method=GET` form that actually sends
  credentials in the query string.
- **Evidence required before flagging:** a real native GET submission carrying
  credentials (not just an absent `method`/`action` on an SPA form).
- **Severity guidance:** native GET with credentials in URL → real finding; SPA form
  with JS submission → **not a finding**.
- **Regression test expectation:** a React form with `onSubmit` + password field, no
  `method`/`action` → **0 "GET password leak" findings**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` (line ~123, "recent FP fixes: **SPA
  forms**, …"); standard-of-proof: "form defaults to GET ≠ credential leak."
- **Review status:** curated (seeded; fix already shipped per audit).
