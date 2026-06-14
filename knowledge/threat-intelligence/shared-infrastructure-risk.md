# Shared Infrastructure Risk

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Problem

The majority of false positives in IP-based threat intelligence arise from shared infrastructure: one IP, many tenants. A malicious actor on shared hosting generates TI reports that wrongly implicate legitimate co-hosted sites.

## CDN / Reverse Proxy Infrastructure

CDN edge IPs serve hundreds of thousands of customers. A malicious site using Cloudflare generates AbuseIPDB/VT reports on a Cloudflare edge IP that also serves banks, government sites, and e-commerce.

### Known CDN ASNs and detection signals

| CDN | ASN | Detection signals |
|---|---|---|
| Cloudflare | AS13335 | `server: cloudflare`, `cf-ray` header, GreyNoise RIOT |
| Fastly | AS54113 | `x-served-by: cache-*`, `via: 1.1 varnish`, GreyNoise RIOT |
| Akamai | AS20940 | `x-akamai-*` headers, `x-check-cacheable` header |
| AWS CloudFront | AS16509 | `x-amz-cf-id` header, `*.cloudfront.net` domain |
| Vercel | AS16509 (via AWS) | `server: Vercel`, `x-vercel-id` header |
| Netlify | AS16509 | `x-nf-request-id` header |
| Google | AS15169 | `via: 1.1 google`, Google ASN |

**Rule**: If the IP's ASN is a CDN + GreyNoise `riot: true` → suppress any IP-level TI finding. Check only URL-level findings for the specific resource being loaded.

## Shared Hosting

Traditional shared hosting (Bluehost, SiteGround, GoDaddy) places thousands of sites on the same IP.

**Detection signals**:
- AbuseIPDB `usageType: Data Center/Web Hosting/Transit`
- Shodan shows `Server` header variants for many domains on one IP
- Reverse DNS shows hosting provider hostname

**Rule**: Shared hosting IP with abuse reports → do not report as customer-site finding. Report as "shared hosting environment — audit neighboring tenants" if WADE has contextual access.

## Dynamic Cloud IP Ranges

AWS, GCP, Azure recycle IP blocks. A cloud IP used by a lambda function today may have been used by a botnet 90 days ago.

**Detection signals**:
- AbuseIPDB `lastReportedAt` > 30 days ago
- `usageType: Data Center`
- IP is in AWS/GCP/Azure published IP ranges

**Rule**: Cloud IP with old abuse reports + no current GreyNoise `malicious` classification → downgrade to informational.

## VPN and Tor Exit Nodes

VPN services and Tor exit nodes generate massive AbuseIPDB reports from users who report any unexpected traffic.

**Detection signals**:
- Shodan `tags: vpn` or `tags: tor`
- GreyNoise `classification: unknown` with `tags: tor` or `tags: vpn`
- AbuseIPDB `usageType: VPN`

**Rule**: VPN/Tor IP match is almost always a FP for customer-site threat assessment. The customer's server is not a threat because a visitor used Tor. Surface only if the VPN/Tor IP is in a specifically anomalous context.

## Anycast and Nameserver IPs

Some IPs (Google's 8.8.8.8, Cloudflare's 1.1.1.1) are globally routed to multiple physical hosts. Abuse reports on these are nearly always FPs.

## Impact on Scoring

Apply these shared-infrastructure penalties to any IP-based TI finding:

| Infrastructure Type | Confidence Multiplier |
|---|---|
| CDN (Cloudflare, Fastly, Akamai, CloudFront, Vercel) | 0.05 |
| Major cloud (AWS, GCP, Azure) | 0.20 |
| Shared hosting (Bluehost, SiteGround) | 0.25 |
| VPN / Tor exit | 0.15 |
| ISP / residential (dynamic) | 0.50 |
| Dedicated server (not shared) | 1.00 |

These penalties apply to IP-level TI matches. URL-level matches remain at full confidence even on shared infrastructure — the URL specificity overcomes the shared-IP problem.
