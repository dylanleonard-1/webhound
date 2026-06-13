# Resend DNS and Email Deliverability

**Provider:** Resend · **Authority:** Tier A official docs · **Source:** https://resend.com/docs/dashboard/domains/introduction
**Terms note:** Publicly available docs; detection-relevant summary only.

## DNS records required for Resend sending

To send email from a custom domain via Resend, three DNS records must be configured and
verified. Each record is validated by Resend's verification API before the domain activates.

### SPF

```
Type: TXT
Name: @ (or subdomain prefix)
Value: v=spf1 include:amazonses.com ~all
```

- `include:amazonses.com` because Resend uses AWS SES as its sending infrastructure
- `~all` = soft fail for non-matching sources (recommended over `-all` for forwarding compatibility)
- Hard fail `-all` acceptable for strict policy but may reject legitimate forwards

### DKIM

Resend provides 3 CNAME records that point to AWS SES DKIM keys:

```
Type: CNAME
Name: resend._domainkey
Value: resend._domainkey.amazonses.com

(+ 2 additional CNAME records: xxx1._domainkey, xxx2._domainkey)
```

- DKIM adds cryptographic signature to outgoing mail
- AWS SES handles key rotation automatically via the CNAMEs

### DMARC

```
Type: TXT
Name: _dmarc
Value: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

- `p=none` = monitoring mode (no enforcement). Recommended for initial setup.
- `p=quarantine` = deliver to spam for policy failures
- `p=reject` = reject at SMTP level for failures

## Verification statuses

Resend API reports domain verification state per-record:
- `not_started` — record not yet added
- `pending` — DNS propagating
- `verified` — record confirmed
- `failed` — record incorrect or missing after timeout

## WebHound detection relevance

- Scanning a site's DNS for SPF/DKIM/DMARC presence = email security posture check
- Missing DMARC = `p=none` or absent → spoofing risk flag
- Missing DKIM = no message integrity → phishing surface
- SPF too permissive (`+all`) = major risk
- SPF with both Resend/SES AND another provider: check for duplicate include conflicts

## Domain verification API

`GET /domains/{id}` returns `{ status: "verified" | "failed" | "pending" }` per record.
This is usable by WebHound's scanner to check if a target domain has Resend configured
and whether records are correctly set.

**Related:** [[stripe-webhook-validation]], [[google-oauth-web-flow]].
