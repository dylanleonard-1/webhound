# Google Safe Browsing v4 Lookup API — Technical Reference

Source: https://developers.google.com/safe-browsing/v4/lookup-api
Provider: Google | Authority: Tier A
Ingested: 2026-06-13 | Terms: Google APIs ToS; free API key via Google Cloud Console; usage limits apply; no re-distribution of list data.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What Google Safe Browsing is

Google's real-time URL threat detection service. Checks URLs against Google's continuously updated threat lists covering malware, phishing, unwanted software, and potentially harmful applications. Used by Chrome, Firefox, Safari, and Android.

## Lookup API Endpoint

```
POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY
```

Authentication: API key as query parameter. Key obtained from Google Cloud Console.

## Request Format

```json
{
  "client": {"clientId": "your-app-id", "clientVersion": "1.0"},
  "threatInfo": {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [{"url": "https://example.com/suspect"}]
  }
}
```

Up to **500 URLs per request**. `threatEntryTypes` must be `["URL"]` for Lookup API.

## Threat Types

| Type | Description |
|---|---|
| `MALWARE` | Malicious software distribution |
| `SOCIAL_ENGINEERING` | Phishing, deceptive pages |
| `UNWANTED_SOFTWARE` | PUPs, adware, browser hijackers |
| `POTENTIALLY_HARMFUL_APPLICATION` | Mobile apps with harmful behavior |

## Response Format

Empty object `{}` if no matches found.

Non-empty when matches exist:
```json
{
  "matches": [
    {
      "threatType": "SOCIAL_ENGINEERING",
      "platformType": "ANY_PLATFORM",
      "threatEntryType": "URL",
      "threat": {"url": "https://example.com/suspect"},
      "cacheDuration": "300s"
    }
  ]
}
```

`cacheDuration`: how long to cache the result (treat URL as unsafe for this period without re-querying).

## Match Semantics

A match means the URL appears on one or more Google Safe Browsing lists. Confidence is high — Google's lists are continuously validated at scale. A match = strong signal for the specific URL.

`threatEntryMetadata`: currently available for `MALWARE/WINDOWS/URL` — includes key-value pairs like `malware_threat_type: landing`.

## URL-Level Specificity

Safe Browsing matches at the **URL level** (path-sensitive). A match on `example.com/malware.exe` does NOT mean `example.com` itself is malicious.

## Update API (alternative)

For high-volume use, the Update API downloads threat list hashes locally for local matching — more efficient than per-URL Lookup API calls. Recommended for > 1000 checks/day.

## Rate Limits

Not fully published in fetched docs. Practical limits via Google Cloud Console quota settings. Free tier: ~10,000 queries/day (verify current limits in Cloud Console).

## Confidence Semantics

- Google Safe Browsing match: very high confidence for the specific URL at that moment
- `cacheDuration` tells you how long to trust the result
- No match: does NOT mean URL is safe — GSB has gaps, newly deployed pages may not yet be listed
- Broader coverage than any single-provider source

## False Positive Risk

- Rare for confirmed GSB matches (Google validates at scale)
- `cacheDuration` expired result: should re-query
- URL normalization: GSB may match canonicalized form — check exact match vs prefix match
- Redirects: GSB checks the submitted URL, not redirect destination — follow redirects and check each hop

## License / Terms

- Google APIs Terms of Service
- Free API key via Google Cloud Console
- Must not re-distribute or re-sell raw list data
- Must display "Google Safe Browsing" attribution in user-facing interfaces where results are shown
- No storing of list data beyond `cacheDuration`

## WebHound Scanner Relevance

High-value source: broadest coverage, high precision, free for reasonable usage.
Use case: check all third-party script URLs, redirect chains, embedded iframes against GSB.
Gap: no Google Safe Browsing client in `scanner/webhound/threat_intel/`.
WADE note: a GSB match is a strong finding regardless of domain reputation — URL-level match is specific enough to report with high confidence.
