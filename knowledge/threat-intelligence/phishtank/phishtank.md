# PhishTank — Source Note

Provider: PhishTank (Cisco Talos) | Focus: Community-verified phishing URLs
Auth: Free API key | Existing client: NOT implemented

## Key Detection Facts
- Community-verified: human voters confirm phishing; verified=yes in dataset
- Dataset: only currently online, verified phishing URLs
- Target field: identifies impersonated brand (PayPal, Apple, bank, etc.)
- Updated hourly; check ETag for efficient polling
- Dataset includes IP/network info per phish

## WebHound Use
- Check third-party URLs from customer pages
- target field useful for brand impersonation context in customer reports
- High precision (community-verified) -- low FP rate
