# AWS CloudFront CDN

**Provider:** AWS CloudFront · **Authority:** Tier A official docs · **Source:** https://docs.aws.amazon.com/cloudfront/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What CloudFront is

AWS CloudFront is a CDN that caches content at edge locations and optionally:
- Terminates TLS at the edge
- Routes to origin (S3, ALB, EC2, API Gateway, custom HTTP origins)
- Integrates with AWS WAF and Shield

## Response headers from CloudFront

| Header | Always present | Notes |
|---|---|---|
| `x-amz-cf-id` | Yes | CloudFront request ID (unique per request) |
| `x-amz-cf-pop` | Yes | Edge POP that served the response (e.g., `IAD89-C1`) |
| `x-cache` | Yes | `Hit from cloudfront` or `Miss from cloudfront` |
| `via` | Yes | `1.1 {id}.cloudfront.net (Amazon CloudFront)` |
| `age` | On cache hit | Seconds the response has been cached |

## TLS (CloudFront TLS options)

- **Viewer Protocol Policy**: HTTP/HTTPS, HTTPS only, or HTTP → HTTPS redirect
- Supports TLS 1.2 and 1.3
- Default certificate: `*.cloudfront.net` (shared)
- Custom domain: ACM certificate required (us-east-1 only for CloudFront)

## Cache behavior (scan relevance)

- CloudFront caches responses based on configured TTL and `Cache-Control` / `Expires` headers
- `x-cache: Hit from cloudfront` = scanner receives cached response, not live origin data
- POST requests: typically not cached; always forwarded to origin
- Headers/cookies not in the cache policy → stripped before forwarding to origin

A scanner receiving cached responses may see stale data if origin content changed.
Force a cache bypass by including a unique query param (if origin accepts it).

## Origin Shield

CloudFront Origin Shield is an additional caching layer between edge nodes and origin.
Reduces origin load. When enabled:
- `x-amz-cf-id` still present
- `x-amz-via-cf-origin-shield: true` may appear

## Geo-blocking

CloudFront geographic restrictions can block by country:
- Uses MaxMind GeoIP database
- Blocked countries receive 403 with `Geo restriction` error

Scanner from a blocked geography → 403 immediately, regardless of WAF rules.

## Signed URLs / Signed cookies

For private content (media streaming, paid content):
- CloudFront validates signed URL or `CloudFront-Policy`, `CloudFront-Key-Pair-Id`,
  `CloudFront-Signature` cookies
- Unsigned requests → 403
- Scanner should detect CloudFront signed URL requirements as access control signal

**Related:** [[aws-waf-detection]], [[cloudflare-waf-detection]].
