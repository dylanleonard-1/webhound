# WebHound — scanner/webhound/engines/secrets/secret_scanner.py
# Passive scanning of page source for hardcoded secrets and credentials.
#
# Safe-mode: reads pre-extracted HTML body and inline scripts only.
# Matched values are NEVER transmitted, stored, or included in full in
# findings. Evidence snippets are truncated and redacted to prevent
# inadvertent key logging.

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Iterator

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "secret_scanner"

_CONTEXT_CHARS = 40
_EXPOSE_PREFIX = 8

# ---------------------------------------------------------------------------
# Framework / CVSS / compliance preset table
# Keyed by secret name. Each entry encodes the worst-case blast radius for
# that specific credential type.
# ---------------------------------------------------------------------------

_PROD_CREDENTIAL_FA = FrameworkAlignment(
    owasp_top10=["A02:2021", "A07:2021", "A09:2021"],
    cwe_ids=["CWE-798", "CWE-312", "CWE-200"],
    nist_controls=["IA-5", "SC-28", "AC-3"],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvss_score=10.0,
    pci_dss=["3.5.1", "8.3.1", "8.6.1"],
    iso_27001=["A.5.17", "A.8.24"],
    soc2=["CC6.1", "CC6.7"],
    hipaa=["164.312(a)(2)(i)", "164.312(d)"],
    exploitability=Exploitability.KNOWN_EXPLOITED,
)

_PAYMENT_CREDENTIAL_FA = FrameworkAlignment(
    owasp_top10=["A02:2021", "A07:2021"],
    cwe_ids=["CWE-798", "CWE-312"],
    nist_controls=["IA-5", "SC-28"],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvss_score=10.0,
    pci_dss=["3.5.1", "8.3.1", "8.6.1", "12.3.3"],
    iso_27001=["A.5.17", "A.8.24"],
    soc2=["CC6.1", "CC6.7"],
    hipaa=[],
    exploitability=Exploitability.KNOWN_EXPLOITED,
)

_HIGH_VALUE_API_FA = FrameworkAlignment(
    owasp_top10=["A02:2021", "A07:2021"],
    cwe_ids=["CWE-798", "CWE-312"],
    nist_controls=["IA-5", "SC-28"],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cvss_score=9.1,
    pci_dss=["3.5.1", "8.3.1"],
    iso_27001=["A.5.17", "A.8.24"],
    soc2=["CC6.1"],
    hipaa=[],
    exploitability=Exploitability.KNOWN_EXPLOITED,
)

_API_FA = FrameworkAlignment(
    owasp_top10=["A02:2021"],
    cwe_ids=["CWE-798"],
    nist_controls=["IA-5"],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_score=7.5,
    pci_dss=["3.5.1", "8.3.1"],
    iso_27001=["A.5.17"],
    soc2=["CC6.1"],
    hipaa=[],
    exploitability=Exploitability.PRACTICAL,
)

_PUBLISHABLE_FA = FrameworkAlignment(
    owasp_top10=["A05:2021"],
    cwe_ids=["CWE-200"],
    nist_controls=["CM-7"],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score=3.7,
    pci_dss=[],
    iso_27001=["A.8.9"],
    soc2=["CC7.1"],
    hipaa=[],
    exploitability=Exploitability.THEORETICAL,
)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    description: str
    remediation: str
    framework: FrameworkAlignment
    # Optional validator. Takes the full match and returns True if it's
    # genuinely a secret (used to drop false positives, e.g. CSS bundle
    # IDs masquerading as JWTs).
    validator: callable | None = None


def _p(
    name: str,
    raw: str,
    severity: Severity,
    confidence: float,
    description: str,
    remediation: str,
    framework: FrameworkAlignment,
    *,
    flags: int = 0,
    validator: callable | None = None,
) -> _SecretPattern:
    return _SecretPattern(
        name=name,
        pattern=re.compile(raw, flags) if flags else re.compile(raw),
        severity=severity,
        confidence=confidence,
        description=description,
        remediation=remediation,
        framework=framework,
        validator=validator,
    )


# ---------------------------------------------------------------------------
# JWT validator — confirm base64 header decodes to `{"alg":..., "typ":"JWT"}`.
# Kills the most common false positive (Tailwind/CSS bundler IDs that look
# like eyJ…eyJ…<long> by coincidence).
# ---------------------------------------------------------------------------


def _looks_like_real_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_b64 = parts[0]
    # Re-pad
    pad = "=" * (-len(header_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(header_b64 + pad)
        header = json.loads(decoded.decode("utf-8", errors="replace"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and (
        "alg" in header or header.get("typ", "").upper() == "JWT"
    )


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

_PATTERNS: list[_SecretPattern] = [
    # ---- AWS ----
    _p(
        "AWS Access Key ID",
        r"\bAKIA[0-9A-Z]{16}\b",
        Severity.CRITICAL, 0.95,
        "An AWS Access Key ID has been published in the page. On its own the ID "
        "isn't enough to log in (it needs the matching secret), but its presence "
        "in client code almost always means the secret is nearby — or already "
        "compromised. Search history will record this leak even after the page "
        "is fixed; the key should be considered burned.",
        "Revoke the key immediately in AWS IAM → Access Keys. Audit CloudTrail "
        "for the last 90 days for any unfamiliar activity tied to this key. "
        "Replace it with an IAM Role attached to whatever workload needs it; "
        "if it must remain an access-key pair, store the credentials in AWS "
        "Secrets Manager or Parameter Store and load them at runtime — never "
        "embed in client code or commit to source.",
        _PROD_CREDENTIAL_FA,
    ),
    _p(
        "AWS Secret Access Key (assignment)",
        r"""(?xi)
            (?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key)
            \s*[:=]\s*
            ['"]([A-Za-z0-9/+=]{40})['"]
        """,
        Severity.CRITICAL, 0.95,
        "An AWS Secret Access Key — the long 40-character partner to an Access "
        "Key ID — has been published. With this value an attacker can do "
        "anything the IAM user/role can do: spin up instances, read S3 buckets, "
        "decrypt KMS-protected secrets, drain billing.",
        "Revoke the key immediately, then check CloudTrail for unauthorised "
        "activity over the credential's entire lifetime — not just since "
        "discovery. Rotate any downstream secrets the key could have decrypted. "
        "Move to IAM roles or short-lived STS credentials.",
        _PROD_CREDENTIAL_FA,
    ),
    _p(
        "AWS Session Token",
        r"\b(?:FQoG|IQoJ|FwoG)[A-Za-z0-9/+=]{300,}\b",
        Severity.HIGH, 0.85,
        "An AWS STS session token has been published. Session tokens are "
        "short-lived (typically 1–12 hours) but they grant the full permission "
        "set of the role that issued them. If the leak is fresh, an attacker "
        "can use it directly without needing to crack anything.",
        "Revoke the issuing role's active sessions in IAM. The token will "
        "expire on its own schedule, but for high-privilege roles wait it "
        "out behind a temporary deny-policy. Audit how the token reached the "
        "browser — usually it's a misconfigured Cognito identity pool or a "
        "server endpoint accidentally rendering credentials into the page.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- GitHub ----
    _p(
        "GitHub Token",
        r"\b(?:ghp|gho|ghs|ghr)_[0-9a-zA-Z]{36}\b|\bgithub_pat_[0-9a-zA-Z_]{82}\b",
        Severity.CRITICAL, 0.95,
        "A GitHub personal-access or app token has been published. Tokens "
        "starting with `ghp_` are user PATs (full read/write to the user's "
        "repos), `gho_` are OAuth app tokens, `ghs_` are GitHub App "
        "installation tokens, `github_pat_` are fine-grained PATs. Any of "
        "these in client-visible HTML mean a third party can read your "
        "private code or push commits.",
        "Revoke at https://github.com/settings/tokens (or the app's "
        "installation page). For CI/CD, use GitHub Actions secrets and "
        "OIDC-issued short-lived tokens rather than long-lived PATs.",
        _PROD_CREDENTIAL_FA,
    ),
    _p(
        "GitLab Personal Access Token",
        r"\bglpat-[0-9a-zA-Z_\-]{20}\b",
        Severity.CRITICAL, 0.95,
        "A GitLab personal access token has been published. Equivalent risk "
        "to a GitHub PAT — full access to the user's projects, including "
        "private source code and CI/CD variables.",
        "Revoke at GitLab → User Settings → Access Tokens. Use a GitLab "
        "service account with the minimum permissions instead of a personal "
        "token, and store it in GitLab CI/CD variables marked as masked + "
        "protected.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- Payment processors ----
    _p(
        "Stripe Live Secret Key",
        r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        Severity.CRITICAL, 0.95,
        "A Stripe LIVE secret key (`sk_live_…`) has been published. This key "
        "can charge cards, issue refunds, read customer data, and create "
        "Connect accounts on your behalf. Even brief exposure typically "
        "results in fraudulent charges within hours.",
        "Roll the key immediately at https://dashboard.stripe.com/apikeys "
        "(click 'Roll key'). Review recent charges, refunds, and Connect "
        "activity for anything unfamiliar. Move all Stripe API calls to your "
        "backend; the browser should only ever see publishable keys.",
        _PAYMENT_CREDENTIAL_FA,
    ),
    _p(
        "Stripe Live Publishable Key",
        r"\bpk_live_[0-9a-zA-Z]{24,}\b",
        Severity.LOW, 0.7,
        "A Stripe LIVE publishable key was found in client code. Publishable "
        "keys are designed to be in the browser — they can tokenise card "
        "details but can't charge, refund, or read existing data. The only "
        "real risk is somebody copying the key into a competing site that "
        "uses your Stripe account for the test environment.",
        "Restrict the key to specific domains under Stripe Dashboard → "
        "Developers → API keys → Restrict. This stops the key working "
        "anywhere except your origins.",
        _PUBLISHABLE_FA,
    ),
    _p(
        "Stripe Test Secret Key",
        r"\bsk_test_[0-9a-zA-Z]{24,}\b",
        Severity.MEDIUM, 0.85,
        "A Stripe TEST secret key has been published. Test keys can't touch "
        "real money, but they can create test charges and view test customer "
        "records. They also strongly suggest the same code path puts the "
        "LIVE key in the same place — worth checking immediately.",
        "Roll the test key in the Stripe Dashboard and move it server-side. "
        "Audit the surrounding code path to confirm `sk_live_` isn't being "
        "rendered the same way in production.",
        _API_FA,
    ),

    # ---- LLM / AI providers ----
    _p(
        "OpenAI API Key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        Severity.HIGH, 0.85,
        "An OpenAI API key has been published. These keys are billed by usage "
        "and quotas can run up surprisingly fast — bots scrape GitHub for them "
        "constantly and start running queries within minutes of exposure.",
        "Revoke immediately at https://platform.openai.com/api-keys. Check the "
        "Usage tab for unfamiliar request spikes. For client-side AI features, "
        "proxy through your backend with per-user rate limits rather than "
        "shipping the key to the browser.",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Anthropic API Key",
        r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{80,}\b",
        Severity.HIGH, 0.9,
        "An Anthropic Claude API key has been published. Same blast radius as "
        "OpenAI keys — usage-billed, scraped continuously.",
        "Revoke at https://console.anthropic.com/settings/keys. Check billing "
        "for unexpected usage. Proxy through your backend rather than "
        "client-side.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- Communications / mail ----
    _p(
        "SendGrid API Key",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43,}",
        Severity.HIGH, 0.95,
        "A SendGrid API key has been published. An attacker can send mail "
        "from your verified sender domains — phishing your own customers "
        "from your real email infrastructure, which bypasses SPF/DKIM/DMARC "
        "checks that protect you from spoofers.",
        "Revoke at SendGrid → Settings → API Keys. Audit recent send activity "
        "for spam runs. If keys must remain in app code, use the minimum "
        "permission scope (Mail Send only, not Admin).",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Mailgun API Key",
        r"\bkey-[a-f0-9]{32}\b",
        Severity.HIGH, 0.85,
        "A Mailgun API key has been published. Same exfiltration risk as "
        "SendGrid: attackers send phishing from your authenticated domain.",
        "Revoke in Mailgun Dashboard → Account → API Security. Rotate domain "
        "credentials. Audit recent send logs for unfamiliar bursts.",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Twilio Account SID",
        r"\bAC[a-f0-9]{32}\b",
        Severity.MEDIUM, 0.75,
        "A Twilio Account SID is in the page source. The SID itself is the "
        "public identifier, but seeing it usually means the matching auth "
        "token is somewhere nearby — and the auth token can send SMS, place "
        "calls, and rack up usage charges on your account.",
        "Confirm whether the matching auth token (`SK…`) is also exposed; "
        "if so, rotate it under Twilio Console → API keys & tokens. Use "
        "subaccounts with constrained permissions for application code.",
        _API_FA,
    ),
    _p(
        "Twilio Auth Token",
        r"""(?xi)
            (?:twilio[_-]?(?:auth[_-]?)?token|TWILIO_AUTH_TOKEN)
            \s*[:=]\s*
            ['"]([a-f0-9]{32})['"]
        """,
        Severity.HIGH, 0.85,
        "A Twilio auth token has been published. This token can send SMS, "
        "make/receive calls, and (combined with a SID) authenticates as your "
        "Twilio account. Bots use leaked Twilio tokens for SMS-based 2FA "
        "bypass and toll-fraud campaigns.",
        "Rotate immediately in the Twilio Console. Review recent SMS / "
        "voice usage logs. Move credentials server-side.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- Google / cloud ----
    _p(
        "Google API Key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        Severity.HIGH, 0.9,
        "A Google API key has been published. These keys often have very broad "
        "scope by default — Maps, Translate, Cloud Vision, billing-gated APIs "
        "— and bots scan public sources continuously.",
        "Restrict the key under Google Cloud Console → APIs & Services → "
        "Credentials: limit it to specific HTTP referrers, IP addresses, "
        "and APIs. Set a daily quota cap to bound the cost of any future "
        "leak.",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Google OAuth Client Secret",
        r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
        Severity.HIGH, 0.95,
        "A Google OAuth client secret (GOCSPX-…) has been published. With "
        "this, an attacker can impersonate your application during OAuth "
        "flows — phishing for user consent that grants access to Gmail, "
        "Drive, or Workspace.",
        "Revoke at Google Cloud Console → APIs & Services → Credentials → "
        "OAuth 2.0 Client IDs. Investigate any unfamiliar OAuth grants in "
        "your audit log. Use PKCE for SPA/mobile flows so a leaked client "
        "secret is less damaging.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- Azure ----
    _p(
        "Azure Storage Account Key",
        r"""(?xi)
            (?:accountkey|account[_-]?key)
            \s*=\s*
            ([A-Za-z0-9+/]{86,88}==)
        """,
        Severity.CRITICAL, 0.85,
        "An Azure storage account key has been published. The key grants "
        "full read/write/delete on every container in the storage account, "
        "including blob, file, queue, and table services. Storage keys "
        "rarely get rotated, so historical exposure usually means current "
        "exposure.",
        "Regenerate the key in Azure Portal → Storage account → Access keys. "
        "Switch to SAS tokens (scoped + time-limited) or Azure AD / Managed "
        "Identity for service-to-service access. Audit storage access logs "
        "for unfamiliar IPs.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- DigitalOcean ----
    _p(
        "DigitalOcean Personal Access Token",
        r"\bdop_v1_[a-f0-9]{64}\b",
        Severity.CRITICAL, 0.95,
        "A DigitalOcean API token has been published. The token can create "
        "and destroy droplets, drain databases, and access Spaces — billing "
        "abuse and full data destruction are both on the table.",
        "Revoke at DigitalOcean → API → Tokens. Audit recent droplet "
        "activity for unfamiliar creations. Use scoped OAuth applications "
        "where possible.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- Slack ----
    _p(
        "Slack Bot Token",
        r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}\b",
        Severity.HIGH, 0.9,
        "A Slack bot token (xoxb-…) has been published. Depending on the "
        "bot's OAuth scopes the attacker can read channels (including DMs "
        "the bot is in), post messages impersonating the bot, and exfiltrate "
        "file uploads.",
        "Revoke at Slack API console → Your Apps → OAuth & Permissions. "
        "Audit message history for messages posted by the bot you didn't "
        "expect. Pin tokens behind environment variables.",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Slack User Token",
        r"\bxox[paop]-[0-9]{10,13}(?:-[0-9]{10,13}){1,2}-[0-9a-zA-Z]{24,}\b",
        Severity.HIGH, 0.85,
        "A Slack user-scoped token has been published. User tokens carry the "
        "full permission set of the user that issued them — typically broad "
        "access across the entire workspace, including channel reads and "
        "search.",
        "Revoke at Slack → Account settings, and have the issuing user log "
        "out everywhere. Audit workspace activity for the user's account.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- Discord / Telegram ----
    _p(
        "Discord Bot Token",
        r"\b[MN][A-Za-z\d]{23,30}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{27,}",
        Severity.HIGH, 0.85,
        "A Discord bot token has been published. The bot can read every "
        "message in every server it's a member of, send messages as itself, "
        "kick or ban members (with the right permissions), and exfiltrate "
        "the entire member list.",
        "Reset the token at https://discord.com/developers/applications → "
        "Your Bot → Reset Token. Audit recent message activity for unfamiliar "
        "actions.",
        _HIGH_VALUE_API_FA,
    ),
    _p(
        "Telegram Bot Token",
        r"\b\d{8,12}:[A-Za-z0-9_\-]{35,}",
        Severity.HIGH, 0.85,
        "A Telegram bot token has been published. Anyone with the token can "
        "send messages as the bot to any chat the bot is in, read message "
        "history (when privacy mode is off), and forward messages.",
        "Revoke via @BotFather → /revoke. Send a new /token to generate "
        "a replacement and update your code.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- NPM / package registries ----
    _p(
        "NPM Token",
        r"\bnpm_[A-Za-z0-9]{36,}",
        Severity.CRITICAL, 0.95,
        "An NPM token has been published. With publish-scope, an attacker "
        "can release a malicious version of any package the user owns — "
        "a supply-chain compromise that propagates to every downstream "
        "installer within hours. NPM has been the source of multiple "
        "high-profile supply-chain attacks.",
        "Revoke at https://www.npmjs.com/settings/<user>/tokens. Check for "
        "any unexpected package versions published since the token was "
        "created. Use automation/granular tokens with single-package scope "
        "for CI rather than personal tokens.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- DB / connection strings ----
    _p(
        "Database Connection String",
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://"
        r"[A-Za-z0-9_\-]+:[^@\s\"'<>]{4,}@"
        r"[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-]*",
        Severity.CRITICAL, 0.9,
        "A full database connection string (with username + password + host) "
        "has been published. This is the most direct route to your data: "
        "with the credentials and host in hand, an attacker can connect "
        "from anywhere their IP is allow-listed (or always, if the database "
        "is on the public internet).",
        "Rotate the database password immediately. Move connection strings "
        "into a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure "
        "Key Vault) and inject them at runtime. Restrict the database to "
        "an IP allow-list — never leave a managed-database endpoint open "
        "to 0.0.0.0/0.",
        _PROD_CREDENTIAL_FA,
    ),

    # ---- Other SaaS ----
    _p(
        "Datadog API Key",
        r"""(?xi)
            (?:dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key)
            \s*[:=]\s*
            ['"]([a-f0-9]{32})['"]
        """,
        Severity.MEDIUM, 0.85,
        "A Datadog API key has been published. The key can submit metrics, "
        "logs, and events to your Datadog account — used by attackers for "
        "log injection (hiding their own activity) or to drive up Datadog "
        "ingestion costs.",
        "Revoke at Datadog → Organization Settings → API Keys. Use Application "
        "Keys with minimal scopes rather than the master API key when calling "
        "the Datadog API from automation.",
        _API_FA,
    ),
    _p(
        "Sentry DSN with Secret",
        r"\bhttps://[a-f0-9]{32}:[a-f0-9]{32}@[a-z0-9.\-]+/[0-9]+\b",
        Severity.MEDIUM, 0.85,
        "A Sentry DSN with the deprecated `public:secret@` form has been "
        "published. Modern Sentry DSNs are public-only — having a secret "
        "in the URL grants additional API access (project management, "
        "release deploy, event tampering).",
        "Migrate to the public DSN format (no `:secret@`). Revoke the "
        "existing key in Sentry → Settings → Client Keys. Confirm the "
        "frontend uses only the public DSN.",
        _API_FA,
    ),
    _p(
        "Heroku API Key",
        r"""(?xi)
            (?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)
            \s*[:=]\s*
            ['"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]
        """,
        Severity.HIGH, 0.85,
        "A Heroku API key has been published. The key controls every app, "
        "addon, and config var on the Heroku account — deletion, code "
        "deployment, and database access are all in scope.",
        "Revoke at https://dashboard.heroku.com/account → API Key → "
        "Regenerate. Audit recent app changes. Use OAuth-scoped tokens "
        "for CI/CD rather than the user's master API key.",
        _HIGH_VALUE_API_FA,
    ),

    # ---- Private keys ----
    _p(
        "PEM Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        Severity.CRITICAL, 0.99,
        "A PEM-encoded private key has been published. Private keys signal "
        "either a TLS certificate, an SSH key, a JWT signing key, or a code-"
        "signing key — all of which let an attacker impersonate the legitimate "
        "owner. Any certificate or signature produced before today should be "
        "treated as suspect.",
        "Remove the key from source AND from web-accessible paths immediately. "
        "Revoke or rotate every certificate, SSH key pair, or signing key "
        "this PEM could correspond to. Force-roll any JWTs the key may have "
        "signed by changing the signing kid.",
        _PROD_CREDENTIAL_FA,
    ),
    _p(
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}\b",
        Severity.MEDIUM, 0.75,
        "A JSON Web Token (JWT) has been published. JWTs aren't secrets per "
        "se — they're meant to be transmitted — but seeing one hardcoded "
        "into a page usually means one of: (1) a long-lived token shipped "
        "deliberately, which is fine if the scope is read-only and the "
        "expiry is short; (2) a token captured during development and left "
        "in by accident; (3) a session token being reflected back into the "
        "page server-side, which is a session-fixation vulnerability.",
        "Decode the JWT (header/payload are base64) and check three things: "
        "(1) does the `exp` claim show a sensible expiry? (2) is the `aud` "
        "constrained to your service? (3) is this token meant to be public, "
        "or is it leaking a user's session? If it's a session token, treat "
        "this as a session-fixation finding and invalidate the session.",
        _API_FA,
        validator=_looks_like_real_jwt,
    ),

    # ---- Generic catch-all ----
    _p(
        "Generic API secret pattern",
        r"""(?xi)
            (?:api[_-]?(?:key|secret|token)|client[_-]?secret|access[_-]?token|
               auth[_-]?token|private[_-]?key|signing[_-]?secret)
            \s*[:=]\s*
            ['"]([a-zA-Z0-9_\-]{32,})['"]
        """,
        Severity.MEDIUM, 0.4,
        "A variable named like a secret credential (`api_key`, `client_secret`, "
        "`signing_secret`, etc.) was assigned a long opaque value in the page "
        "source. This is a heuristic match — the confidence is low because the "
        "name could be misleading and the value might be a public identifier. "
        "Worth a human eyeball: does the value here belong on the public "
        "internet?",
        "If the value is genuinely public (e.g. a Stripe publishable key, a "
        "Sentry public DSN), document that so future scans expect to see it. "
        "If it's actually a secret, rotate it and move it server-side — "
        "either to a secrets manager or to an environment-variable-injected "
        "build artifact.",
        _API_FA,
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact_match(match: str) -> str:
    exposed = match[:_EXPOSE_PREFIX].rstrip()
    suffix = "..." if len(match) > _EXPOSE_PREFIX else ""
    return f"{exposed}{suffix}"


def _context_snippet(text: str, start: int, end: int) -> str:
    ctx_start = max(0, start - 20)
    ctx_end = min(len(text), end + 20)
    raw = text[ctx_start:ctx_end]
    match_in_ctx = text[start:end]
    snippet = raw.replace(match_in_ctx, _redact_match(match_in_ctx) + "<REDACTED>", 1)
    prefix = "…" if ctx_start > 0 else ""
    suffix = "…" if ctx_end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _scan_text(text: str) -> Iterator[tuple[_SecretPattern, str, str]]:
    for sp in _PATTERNS:
        for m in sp.pattern.finditer(text):
            full_match = m.group(0)
            if sp.validator is not None and not sp.validator(full_match):
                continue
            redacted = _redact_match(full_match)
            context = _context_snippet(text, m.start(), m.end())
            yield sp, redacted, context


def _make_finding(sp: _SecretPattern, redacted: str, context: str, url: str) -> Finding:
    return Finding(
        title=f"Hardcoded {sp.name} found in page source",
        description=sp.description,
        severity=sp.severity,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.PATTERN_MATCH,
            content=context,
            location=url,
            source_engine=_ENGINE,
            extra={"pattern_name": sp.name, "redacted_prefix": redacted},
        )],
        confidence=sp.confidence,
        remediation=sp.remediation,
        framework=sp.framework,
        scanner_engine=_ENGINE,
        metadata={"url": url, "pattern": sp.name, "redacted_prefix": redacted},
    )


class SecretScannerEngine:
    """Scans HTML body and inline scripts for hardcoded credentials.

    Findings are de-duplicated per (pattern_name, URL) pair so that a single
    leaked key appearing in both HTML and a script block is reported once.

    Safe-mode: read-only. Matched values are redacted in evidence; the full
    secret is never stored, logged, or transmitted. Some patterns carry a
    validator (e.g. the JWT pattern decodes the header to confirm it's a
    real JWT rather than a base64-coincidence in a CSS bundle ID).
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        *,
        html_body: str | None = None,
    ) -> list[Finding]:
        url = artifacts.url
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        texts: list[str] = []
        if html_body:
            texts.append(html_body)
        for script_body in artifacts.inline_scripts:
            if script_body and script_body not in texts:
                texts.append(script_body)

        for text in texts:
            for sp, redacted, context in _scan_text(text):
                key = (sp.name, url)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_make_finding(sp, redacted, context, url))

        return findings
