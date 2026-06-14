# OpenPhish — Source Note

Provider: OpenPhish | Focus: Phishing URLs (automated discovery)
Auth: Org account for paid; community feed free | Existing client: Normalizer only

## Key Detection Facts
- Community feed: openphish.com/feed.txt -- plain URL list, no auth required
- Paid feed: SQLite DB with brand, SSL, IP/ASN metadata; 15-minute updates
- Automated (not community-voted) -- different coverage profile than PhishTank

## WebHound Use
- Community feed accessible without auth for baseline phishing URL matching
- Check customer-page URLs against community feed
- Paid feed would provide brand context for customer reporting
