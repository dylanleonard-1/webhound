# Google Safe Browsing — Source Note

Provider: Google | Focus: Malware and phishing URLs at scale
Auth: Free API key (Google Cloud Console) | Existing client: NOT implemented

## Key Detection Facts
- Threat types: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION
- Up to 500 URLs per request (batch-friendly)
- cacheDuration: result valid for this period; re-query after expiry
- URL-level specificity: path-sensitive matching
- Match = URL on one or more Google threat lists

## WebHound Use
- Highest priority TI source: precision, scale, continuous updates
- Check all third-party script URLs, redirect destinations, iframe srcs
- GSB match = strong finding (no additional source corroboration required)
- Must display Google Safe Browsing attribution in customer-facing outputs
