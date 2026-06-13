# FP/bug: CSP hosts counted but not represented as THIRD_PARTY_DOMAIN graph nodes

- **Engine area:** third-party-domains + Security Graph
  (`scanner/webhound/graph/graph_builder.py`, `relationship_extractor.py`,
  `graph_export.py`).
- **Original bad behavior:** third-party hosts referenced in the CSP were **counted**
  in one place but **not passed through as `THIRD_PARTY_DOMAIN` graph nodes**, so the
  graph's third-party view and the counts disagreed. Related root cause: the graph
  mints one `API_ENDPOINT` node **per network request, keyed on the query-bearing
  URL, with no `looks_like_api` filter**, inflating node/edge counts (~45×) and
  drowning real third-party-domain signal.
- **Why it was a false positive / data bug:** the third-party picture was wrong —
  inflated, inconsistent, and not grounded in a clean domain model. Vanity node/edge
  totals (`1505 nodes`, `~1099 "APIs"`) are noise, not signal.
- **Correct behavior:** (a) filter network artifacts through `looks_like_api()`
  before minting `API_ENDPOINT` nodes; (b) key nodes on the **bare** URL (strip
  query); (c) ensure CSP-referenced third-party hosts are consistently modeled as
  `THIRD_PARTY_DOMAIN` nodes so counts and graph agree.
- **Evidence required before flagging:** a real, deduped third-party domain (not a
  per-request, query-variant artifact).
- **Severity guidance:** third-party domains are context/risk inputs (see
  `third-party-domain-risk/`), not standalone findings; counts must be honest.
- **Regression test expectation:** a Next.js/Vercel site → `THIRD_PARTY_DOMAIN`
  nodes match the deduped third-party host set; "APIs" reflects the API-filtered,
  query-stripped count (~24, not ~1099).
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` (line ~123, "recent FP fixes:
  **third-party graph**"); `WEBHOUND_PRODUCT_REVIEW.md` (graph node inflation:
  `graph_builder.py:220-224`, `relationship_extractor.py:33`, `graph_export.py:51`).
- **Review status:** curated (seeded; graph fix is partly separate work per PRODUCT
  REVIEW — confirm current state before relying on counts).
