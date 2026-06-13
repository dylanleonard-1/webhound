# GitHub Secret Scanning

**Provider:** GitHub · **Authority:** Tier A official docs · **Source:** https://docs.github.com/en/code-security/secret-scanning
**Terms note:** Publicly available docs; detection-relevant summary only.

## What secret scanning detects

GitHub Secret Scanning scans repository content (commits, issues, pull requests, wikis,
discussions) for known secret patterns. It runs on every push for public repos and
optionally for private repos (GitHub Advanced Security license required).

## Supported patterns (selected, detection-relevant)

GitHub maintains 200+ partner patterns. Key patterns:

| Provider | Pattern detected |
|---|---|
| Stripe | `sk_live_[0-9a-zA-Z]{24}`, `rk_live_[0-9a-zA-Z]{24}` |
| AWS | `AKIA[0-9A-Z]{16}` (access key), `[0-9a-zA-Z/+]{40}` (secret key, contextual) |
| Google | `AIza[0-9A-Za-z\-_]{35}` (API key), `ya29\.[0-9A-Za-z\-_]+` (OAuth token) |
| GitHub | `ghp_[a-zA-Z0-9]{36}` (PAT), `ghs_[a-zA-Z0-9]{36}` (app token) |
| Slack | `xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]{32}` |
| Twilio | `SK[0-9a-fA-F]{32}` |

## Push protection

When push protection is enabled:
- GitHub blocks pushes containing known secret patterns
- Developer receives error message with secret location and instructions to remediate
- Can be bypassed with `--bypass-secret-scanning` flag (audit-logged)
- Organization admins can require push protection (cannot be bypassed by repo admins)

## Partner notifications

When a secret is detected in a public repo:
- GitHub notifies the partner (e.g., Stripe, AWS) automatically
- Partner may revoke the credential immediately without notification to repo owner
- Repo owner also receives email notification
- Secret is flagged in the GitHub Security tab → Secret Scanning alerts

## Custom patterns (GHAS)

GitHub Advanced Security allows custom regex patterns:
```
Pattern name: WebHound API Key
Secret format: (webhound_[a-zA-Z0-9]{32})
```
- Scans for proprietary tokens/keys in org repos
- Alerts appear in Security → Secret Scanning

## WebHound scanner context

When WebHound scans a target's public GitHub repositories:
- Look for exposed API keys, tokens, credentials in public code
- Check for high-entropy strings in config files (.env.example, config.yaml, docker-compose.yml)
- Common locations: hardcoded in test files, committed .env files, CI workflow files
- GitHub's Secret Scanning only runs on GitHub repos; WebHound's scanner should run equivalent pattern matching on any hosted code

## Gitleaks-compatible patterns

WebHound uses Gitleaks (from Phase 6B) for local secret scanning. Gitleaks rules align with GitHub's patterns. Key diff:
- GitHub scans all history; Gitleaks can be run on specific commit ranges
- GitHub notifies partners; Gitleaks only reports to the scanner operator

**Related:** [[cloudflare-waf-detection]], [[stripe-webhook-validation]].
