# Google OAuth 2.0 Web Server Flow

**Provider:** Google · **Authority:** Tier A official docs · **Source:** https://developers.google.com/identity/protocols/oauth2/web-server
**Terms note:** Publicly available docs; detection-relevant summary only.

## Flow overview

```
Browser → App Server → Google Authorization Server → App Server → Google APIs
```

1. App redirects browser to `https://accounts.google.com/o/oauth2/v2/auth` with params
2. User consents → Google redirects back to `redirect_uri` with `code=` param
3. App server exchanges code for tokens at token endpoint
4. App uses `access_token` to call Google APIs; `refresh_token` for long-lived access

## Authorization endpoint params

| Param | Required | Notes |
|---|---|---|
| `client_id` | Yes | From Google Cloud Console |
| `redirect_uri` | Yes | Must be pre-registered in OAuth app settings |
| `response_type` | Yes | Always `code` for web server flow |
| `scope` | Yes | Space-separated scopes (e.g., `openid email profile`) |
| `state` | Recommended | CSRF protection — random value verified on callback |
| `access_type` | Optional | `offline` to get refresh token |
| `prompt` | Optional | `consent` forces consent screen; `select_account` forces account picker |
| `code_challenge` | Optional | PKCE (S256) — required for public clients |

## Token exchange endpoint

```
POST https://oauth2.googleapis.com/token
Content-Type: application/x-www-form-urlencoded

code=<authorization_code>&
client_id=<>&
client_secret=<>&
redirect_uri=<exactly_as_in_auth_request>&
grant_type=authorization_code
```

Response: `{ access_token, expires_in, token_type, scope, refresh_token, id_token }`

## Error codes (scanner sees these as HTTP responses)

| Error | Condition |
|---|---|
| `redirect_uri_mismatch` | `redirect_uri` not in pre-registered list |
| `invalid_client` | Bad `client_id` or `client_secret` |
| `invalid_grant` | Code already used / expired / wrong `redirect_uri` |
| `access_denied` | User denied consent or app not approved |
| `invalid_scope` | Requested scope not allowed for this app type |

## Security scan relevance

WebHound checks OAuth implementations for:
- **State parameter absent or constant:** CSRF attack surface
- **redirect_uri whitelisted too broadly:** e.g., `https://*.attacker.com/` open redirect
- **Authorization code reuse:** server should reject second use
- **Access token in URL fragment:** OAuth implicit flow (deprecated; tokens in logs)
- **PKCE absent on public clients:** authorization code interception risk
- **Refresh token storage:** if stored in localStorage, XSS can steal it

## Google-specific considerations

- Refresh tokens expire after 6 months of non-use
- Tokens are revoked if user changes password (for `email`/`profile` scopes)
- For `offline_access`, consent screen must include refresh token grant
- OAuth 2.0 Playground at `developers.google.com/oauthplayground` allows manual flow testing

**Related:** [[resend-dns-deliverability]], [[stripe-webhook-validation]].
