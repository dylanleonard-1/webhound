# WebHound Alpha — Bug Report Template

Copy this template for each bug you find.  
File as a GitHub issue (if you have access) or email to the maintainer.  
One bug per report.

---

## Bug Summary

_One sentence describing what went wrong._

---

## Environment

| Field | Your value |
|---|---|
| **Operating System** | (e.g., macOS 14.4, Ubuntu 22.04, Windows 11 + WSL2) |
| **Browser** | (e.g., Chrome 124, Firefox 125, Safari 17) |
| **Docker version** | (output of `docker version --format '{{.Server.Version}}'`) |
| **Docker Compose version** | (output of `docker compose version`) |
| **WebHound git commit** | (output of `git rev-parse --short HEAD`) |
| **Affected area** | (scanner / backend / frontend / Docker / docs) — pick one |

---

## Severity

Mark one:

- [ ] **Blocker** — prevents completing the basic demo flow; system unusable or data loss
- [ ] **High** — core feature broken with no workaround
- [ ] **Medium** — feature partially broken; workaround exists
- [ ] **Low** — minor UX issue, cosmetic defect, or confusing text

---

## Affected Area

Mark one:

- [ ] **Scanner** — scan jobs, findings, engine output, WADE baseline comparison
- [ ] **Backend** — API responses, authentication, database, Celery worker
- [ ] **Frontend** — Next.js UI, forms, display of results, navigation
- [ ] **Docker** — compose setup, container health, build failures
- [ ] **Docs** — incorrect or missing documentation, setup guide errors

---

## Steps to Reproduce

_List the exact steps to trigger the bug. Be specific._

1. 
2. 
3. 

---

## Expected Behavior

_What you expected to happen._

---

## Actual Behavior

_What actually happened. Include the exact error message, HTTP status code, or unexpected UI state._

---

## Logs

Paste the relevant log output. Trim to the ~30 lines around the error.

```bash
# Get API logs:
docker compose logs --tail=50 api

# Get worker logs:
docker compose logs --tail=50 worker
```

<details>
<summary>Log output (click to expand)</summary>

```
paste log output here
```

</details>

---

## API Request / Response (if applicable)

If the bug is in the API, include the exact request and response.

```bash
# Example:
curl -s -X POST http://localhost:8000/scan-jobs \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"website_id":"...","profile":"quick"}'
```

Response:

```json
{
  "paste": "response here"
}
```

---

## Screenshots

_Attach screenshots or screen recordings if the bug is visual._

---

## Additional Context

_Any other information that would help reproduce or diagnose the bug._

- Did this happen consistently or intermittently?
- Were you running multiple scans at the same time?
- Did you restart the stack recently?
- Anything unusual about your environment?

---

## Checklist Before Submitting

- [ ] I filled in all Environment fields above
- [ ] I selected a Severity and Affected Area
- [ ] I listed specific, reproducible steps
- [ ] I included relevant log output or API response
- [ ] This is a single bug (I'll file a separate report for each additional bug)
