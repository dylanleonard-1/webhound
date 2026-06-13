# FP: auth-gated `/admin` returning 200 (SPA shell) flagged as an exposed admin panel

- **Engine area:** sensitive-paths / admin-panel detection.
- **Original bad behavior:** a request to `/admin` returning **HTTP 200** was flagged
  as an **exposed admin panel** — even though the 200 was just the SPA's HTML shell,
  with the real admin UI/API gated behind authentication.
- **Why it was a false positive:** on a client-rendered app, **almost every route
  returns 200** (the same shell), and the auth check happens in JS / on the API. A
  200 at `/admin` is **not** evidence the admin panel is accessible. "Path returns
  200" ≠ "exposed admin."
- **Correct behavior:** gate the finding — require evidence of **actual access**
  (admin content rendered without auth, an unauthenticated admin API 200 with admin
  data, or a redirect-to-login *absence*). A 200 SPA shell + a login redirect / auth
  wall = not exposed.
- **Evidence required before flagging:** unauthenticated access to **admin
  functionality/content**, not a 200 status code alone.
- **Severity guidance:** genuinely unauthenticated admin access → High/Critical;
  auth-gated 200 shell → **not a finding**. (Note: `robots.txt` *advertising*
  `/admin` is a separate, minor LOW true-positive — it leaks the path, but isn't
  "exposed admin.")
- **Regression test expectation:** SPA `/admin` → 200 shell that redirects to login
  / shows no admin content unauthenticated → **0 "exposed admin" findings**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` (line ~123, "recent FP fixes:
  **exposed-admin gate**, …"); standard-of-proof: "/admin exists ≠ exposed admin."
- **Review status:** curated (seeded; gate already shipped per audit).
