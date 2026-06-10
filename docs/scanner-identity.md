# Scanner Identity (Phase 3.3)

WebHound presents one consistent, honest public identity on every scan. This
doc explains where it lives, how traffic uses it, and how site owners /
providers verify legitimate WebHound traffic.

## Single source of truth

All identity values live in **`scanner/webhound/identity.py`** — the only place
they are defined:

| Field | Value |
|---|---|
| `SCANNER_NAME` | `WebHoundScanner` |
| `SCANNER_VERSION` | `1.0` |
| `SCANNER_USER_AGENT` | `WebHoundScanner/1.0 (+https://webhoundsecurity.com/scanner)` |
| `SCANNER_DOCS_URL` | `https://webhoundsecurity.com/scanner` |
| `SCANNER_VERIFICATION_URL` | `https://webhoundsecurity.com/verification` |
| `SCANNER_IP_RANGES_URL` | `https://webhoundsecurity.com/ip-ranges` |
| `SCANNER_CONTACT` | `security@webhoundsecurity.com` |

`identity_dict()` returns the safe, public subset served by the API and stamped
into scan telemetry. **Never** add secrets, env, or internal infrastructure here.

### Changing the version / identity
Edit `identity.py` only. To bump the version, change `SCANNER_VERSION`; the
User-Agent recomposes automatically. Treat a User-Agent rename as a coordinated
change — customers may have allowlisted the previous string.

## How the User-Agent is applied

The UA flows from one place to all outbound scanner traffic:

```
webhound/identity.py : SCANNER_USER_AGENT
   ├── core/http_client.py  WEBHOUND_USER_AGENT  (back-compat alias)
   └── models/target.py     ScanOptions.user_agent  (default)
            └── SafeHttpClient sends it on every GET/HEAD
            └── orchestrator passes scan_options.user_agent to the browser pass
```

Because the static crawler, API probes, JS fetches, monitoring scans, and
admin-triggered scans all run through `SafeHttpClient` / `ScanOptions`, they
inherit the same identity automatically. We **never** spoof a browser or other
crawler — identification is honest by design.

## API endpoint

`GET /scanner/identity` (public, no auth) returns `identity_dict()`:

```json
{
  "scanner_name": "WebHoundScanner",
  "scanner_version": "1.0",
  "user_agent": "WebHoundScanner/1.0 (+https://webhoundsecurity.com/scanner)",
  "verification_url": "https://webhoundsecurity.com/verification",
  "docs_url": "https://webhoundsecurity.com/scanner",
  "ip_ranges_url": "https://webhoundsecurity.com/ip-ranges",
  "contact": "security@webhoundsecurity.com"
}
```

## Public pages

- `/scanner` — what WebHound is + how to verify our traffic.
- `/verification` — DNS TXT / meta / `.well-known` / provider connection.
- `/ip-ranges` — egress note (static IPs coming soon — we do not publish IPs we
  don't control).

## Telemetry

Every scan stamps `result.metadata["scanner_identity"] = identity_dict()`
(observability only — no findings/scoring impact).

## Future: static IPs & reverse DNS

Today WebHound runs on managed cloud infrastructure with **dynamic egress**, so
we do not publish a fixed IP allowlist (listing IPs we don't control would be
inaccurate). When dedicated static scanner egress exists:

1. Add the ranges to `identity.py` (e.g. a `SCANNER_IP_RANGES` list) + expose
   them in `identity_dict()` / the `/scanner/identity` endpoint.
2. Publish them on the `/ip-ranges` page.
3. Configure reverse DNS (PTR) → `scanner.webhoundsecurity.com` and document it.

## How providers / customers verify WebHound

1. **User-Agent** — `WebHoundScanner/1.0 (+…/scanner)` (honest, consistent).
2. **`GET /scanner/identity`** — machine-readable identity document.
3. **Published IP ranges + PTR** — once static egress exists (see above).
