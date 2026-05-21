---
name: Bug Report
about: Report a defect in WebHound
labels: bug
---

## Summary

A one-sentence description of the bug.

## Environment

- WebHound version / git commit:
- OS and Docker version:
- Scan profile used (quick / standard / deep / monitor):
- Browser (if frontend issue):

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error messages, status codes, or screenshots.

## Logs

Paste relevant log output (trim to the relevant section):

```
docker compose logs --tail=50 api
docker compose logs --tail=50 worker
```

<details>
<summary>Log output</summary>

```
paste here
```

</details>

## API Request / Response (if applicable)

```
curl -s -X <METHOD> http://localhost:8000/<path> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '<body>'
```

Response:
```json
{
  "paste": "here"
}
```

## Severity Assessment

- [ ] Critical — system unusable, data loss, or security regression
- [ ] High — core feature broken, no workaround
- [ ] Medium — feature partially broken, workaround exists
- [ ] Low — minor UX or cosmetic issue

## Additional Context

Any other information that might be relevant (related issues, attempted workarounds, etc.).
