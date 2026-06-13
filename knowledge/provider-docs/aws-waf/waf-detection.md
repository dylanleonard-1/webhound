# AWS WAF Detection and Response Signatures

**Provider:** AWS WAF / AWS Shield · **Authority:** Tier A official docs · **Source:** https://docs.aws.amazon.com/waf/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What AWS WAF is

AWS WAF is a web application firewall deployed in front of:
- **Amazon CloudFront** distributions
- **Application Load Balancers (ALB)**
- **Amazon API Gateway**
- **AWS AppSync** GraphQL APIs

## Managed rule groups

AWS provides managed rule groups (free + paid):
- `AWSManagedRulesCommonRuleSet` — core rule set (SQLi, XSS, LFI/RFI, size limits)
- `AWSManagedRulesSQLiRuleSet` — SQL injection rules
- `AWSManagedRulesKnownBadInputsRuleSet` — known bad payloads
- `AWSManagedRulesBotControlRuleSet` — bot detection (IP reputation + browser fingerprinting)
- `AWSManagedRulesATPRuleSet` — account takeover prevention

## Response indicators for blocked requests

When AWS WAF blocks a request:
- Default: 403 Forbidden with default HTML body containing "Request blocked"
- Custom responses: operator-configurable HTTP status + body
- `x-amzn-requestid` header (API Gateway); `x-amz-request-id` (ALB/CloudFront)
- `x-amzn-trace-id` on requests passing through (not blocked)

Blocked response body pattern (default custom response):
```html
<!DOCTYPE html><html>...Request blocked...</html>
```

## Bot Control rule group

When `AWSManagedRulesBotControlRuleSet` is active:
- Requests from known bot user-agents → BLOCK
- Requests with browser-mismatched fingerprint → CHALLENGE (CAPTCHA)
- Challenge type: JavaScript challenge or CAPTCHA widget
- Sets cookie `aws-waf-token` (encrypted challenge token) after passing

`aws-waf-token` cookie format: base64-encoded encrypted data. Required on subsequent
requests to avoid repeated challenges. Not reproducible without executing AWS's
challenge JavaScript.

## Rate-based rules

AWS WAF supports rate-based rules:
- Count requests per IP per 5-minute window
- Action on threshold: BLOCK, CAPTCHA, or CHALLENGE
- Scanner exceeding threshold → blocked for remainder of 5-minute window

## AWS Shield (DDoS)

- **Shield Standard**: automatic for all AWS customers, layer 3/4 DDoS protection
- **Shield Advanced**: layer 7 DDoS protection, WAF integration, attack notification

Scanner traffic at high volume to an ALB/CloudFront origin may trigger Shield Standard
if it resembles volumetric attack patterns.

## Identifying AWS WAF-protected sites

- `x-amz-cf-id` header (CloudFront)
- `x-amzn-requestid` (API Gateway)
- Response 403 with `RequestId` in XML (API Gateway)
- IP resolving to CloudFront edge (AS16509, Amazon)
- `server: CloudFront` or `via: 1.1 {id}.cloudfront.net (CloudFront)`

## Scanner allowlisting

AWS WAF allows IP set exemptions:
- Create an IP set with scanner CIDR ranges
- WAF rule: if IP in {scanner-ip-set} → ALLOW (override block rules)
- Via AWS Console, CDK, or `aws wafv2 create-ip-set` CLI command

**Related:** [[cloudflare-waf-detection]], [[aws-cloudfront-cdn]].
