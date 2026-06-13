# FP: social/marketing link counted as an "API endpoint"

- **Engine area:** API/endpoint discovery
  (`scanner/webhound/engines/api_discovery/endpoint_discovery.py`).
- **Original bad behavior:** "API surface mapped: N endpoint(s)" where the sole
  "endpoint" was a **social link** (`https://x.com/webhoundsecurity`).
  `_gather_endpoints` (`:248-277`) scanned inline-script bodies with an absolute-URL
  regex (`:104`); the only filter was a binary-asset-extension skip — **no external-
  host / social / API-shape filter**. Any absolute URL in a `__NEXT_DATA__`/JSON-LD
  blob became an "endpoint" (×19).
- **Why it was a false positive:** a Twitter/marketing profile URL is **not an API
  surface**. "URL exists in page" ≠ "API endpoint."
- **Correct behavior:** drop hosts that aren't same-origin **and** aren't
  API-shaped; explicitly exclude social/marketing domains; only count URLs that look
  like APIs (path tokens / JSON / fetch-initiated). The `_classify()` tags
  (`:213-245`) already exist to require ≥1 API tag.
- **Evidence required before flagging:** same-origin OR API-shaped URL (path/JSON/
  fetch initiator), not a bare absolute URL.
- **Severity guidance:** INFO at most; never inflate. Excluded items should not be
  counted at all.
- **Regression test expectation:** a page whose only external URL is a social link
  → **0 "API endpoint" findings**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` ("LIKELY FALSE POSITIVES" #1; code change
  `endpoint_discovery.py:248-277`).
- **Review status:** curated (seeded from audit).
