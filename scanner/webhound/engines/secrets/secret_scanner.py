# WebHound — scanner/webhound/engines/secrets/secret_scanner.py
# Passive scanning of page source for hardcoded secrets and credentials.
#
# Safe-mode: reads pre-extracted HTML body and inline scripts only.
# Matched values are NEVER transmitted, stored, or included in full in findings.
# Evidence snippets are truncated and redacted to prevent inadvertent key logging.
#
# Patterns covered:
#   • AWS Access Key IDs         (AKIA…)
#   • GitHub tokens              (ghp_, gho_, ghs_, github_pat_)
#   • Stripe live/test keys      (sk_live_, pk_live_, sk_test_)
#   • Google API keys            (AIza…)
#   • Slack tokens               (xoxb-, xoxp-)
#   • PEM private keys           (-----BEGIN … PRIVATE KEY-----)
#   • JSON Web Tokens            (eyJ…)
#   • Generic high-entropy secrets in common assignment patterns

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "secret_scanner"

# Maximum characters of context shown around a match (before truncation).
_CONTEXT_CHARS = 40
# Prefix length exposed in evidence (e.g. "AKIA" + 4 chars → "AKIAXXX...").
_EXPOSE_PREFIX = 8


@dataclass(frozen=True)
class _SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    remediation: str


def _p(name: str, raw: str, severity: Severity, confidence: float, remediation: str) -> _SecretPattern:
    return _SecretPattern(
        name=name,
        pattern=re.compile(raw),
        severity=severity,
        confidence=confidence,
        remediation=remediation,
    )


_PATTERNS: list[_SecretPattern] = [
    _p(
        "AWS Access Key ID",
        r"AKIA[0-9A-Z]{16}",
        Severity.CRITICAL,
        0.95,
        "Revoke the key in AWS IAM immediately. Remove it from source and use "
        "IAM roles or environment variables instead.",
    ),
    _p(
        "GitHub Token",
        r"(?:ghp|gho|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        Severity.CRITICAL,
        0.95,
        "Revoke the token at github.com/settings/tokens. Use GitHub Actions "
        "secrets or environment variables for CI/CD.",
    ),
    _p(
        "Stripe Live Secret Key",
        r"sk_live_[0-9a-zA-Z]{24,}",
        Severity.CRITICAL,
        0.95,
        "Revoke the key in the Stripe Dashboard immediately. Never expose live "
        "Stripe keys in client-side code.",
    ),
    _p(
        "Stripe Live Publishable Key",
        r"pk_live_[0-9a-zA-Z]{24,}",
        Severity.LOW,
        0.70,
        "Stripe publishable keys are designed to be used in frontend code and are "
        "not secret. However, restrict the key to specific domains in your Stripe "
        "Dashboard (Developers → API keys → Publishable key → Restrict) to prevent "
        "misuse if the key is copied.",
    ),
    _p(
        "Stripe Test Key",
        r"sk_test_[0-9a-zA-Z]{24,}",
        Severity.MEDIUM,
        0.85,
        "Stripe test secret keys should not appear in client-side code. While "
        "they cannot access live payment data, they can be used to create test "
        "charges and access your test customer records. Store them server-side "
        "using environment variables.",
    ),
    _p(
        "Google API Key",
        r"AIza[0-9A-Za-z\-_]{35}",
        Severity.HIGH,
        0.90,
        "Restrict the key in the Google Cloud Console (API restrictions, "
        "HTTP referrer restrictions). Consider rotating it.",
    ),
    _p(
        "Slack Bot Token",
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}",
        Severity.HIGH,
        0.90,
        "Revoke the token in the Slack API console. Use environment variables "
        "and never expose bot tokens in browser-side code.",
    ),
    _p(
        "Slack User/App Token",
        r"xox[paop]-[0-9]{10,13}(?:-[0-9]{10,13})*-[0-9a-zA-Z]{24,}",
        Severity.HIGH,
        0.85,
        "Revoke the token in the Slack API console. User tokens grant broad "
        "account access and must be kept server-side.",
    ),
    _p(
        "PEM Private Key",
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        Severity.CRITICAL,
        0.99,
        "Remove the private key from source immediately. Private keys must never "
        "appear in web-accessible files. Rotate all certificates signed with "
        "this key.",
    ),
    _p(
        "JSON Web Token",
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,}",
        Severity.MEDIUM,
        0.75,
        "JWTs in page source indicate a token is being hard-coded or reflected "
        "without expiry. Verify the token is short-lived and intended to be "
        "client-visible.",
    ),
    _p(
        "Generic API Secret",
        r"""(?xi)
            (?:api[_-]?(?:key|secret|token)|client[_-]?secret|access[_-]?token)
            \s*[:=]\s*
            ['"]?([a-zA-Z0-9_\-]{32,})['"]?
        """,
        Severity.MEDIUM,
        0.40,
        "A potential API key or token was detected in the page source. "
        "Verify whether this value is intentionally public. If it is a secret "
        "credential, remove it from client-side code and load it server-side using "
        "environment variables or a secrets manager.",
    ),
]


def _redact_match(match: str) -> str:
    """Return a safe prefix of the match for evidence display."""
    exposed = match[:_EXPOSE_PREFIX].rstrip()
    suffix = "..." if len(match) > _EXPOSE_PREFIX else ""
    return f"{exposed}{suffix}"


def _context_snippet(text: str, start: int, end: int) -> str:
    """Return a short context window around [start:end]."""
    ctx_start = max(0, start - 20)
    ctx_end = min(len(text), end + 20)
    raw = text[ctx_start:ctx_end]
    # Replace the matched portion with a redacted placeholder
    match_in_ctx = text[start:end]
    snippet = raw.replace(match_in_ctx, _redact_match(match_in_ctx) + "<REDACTED>", 1)
    prefix = "…" if ctx_start > 0 else ""
    suffix = "…" if ctx_end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _scan_text(
    text: str, url: str
) -> Iterator[tuple[_SecretPattern, str, str]]:
    """Yield (pattern, redacted_match, context_snippet) for each hit in *text*."""
    for sp in _PATTERNS:
        for m in sp.pattern.finditer(text):
            full_match = m.group(0)
            redacted = _redact_match(full_match)
            context = _context_snippet(text, m.start(), m.end())
            yield sp, redacted, context


def _make_finding(sp: _SecretPattern, redacted: str, context: str, url: str) -> Finding:
    return Finding(
        title=f"Hardcoded {sp.name} found in page source",
        description=(
            f"A pattern matching a {sp.name} was detected in the page source at "
            f"{url}. Hardcoded credentials in client-accessible pages can be "
            f"extracted by attackers to gain unauthorised access to external services. "
            f"Detected value starts with: {redacted}"
        ),
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
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A09:2021"],
            cwe_ids=["CWE-312", "CWE-798"],
            nist_controls=["IA-5"],
        ),
        scanner_engine=_ENGINE,
        metadata={"url": url, "pattern": sp.name},
    )


class SecretScannerEngine:
    """Scans HTML body and inline scripts for hardcoded credentials.

    Findings are de-duplicated per (pattern_name, URL) pair so that a single
    leaked key appearing in both HTML and a script block is reported once.

    Safe-mode: read-only.  Matched values are redacted in evidence; the full
    secret is never stored, logged, or transmitted.
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
        # Always scan inline scripts (already extracted, avoids double-scanning
        # the full body on most pages where HTML == inline scripts).
        for script_body in artifacts.inline_scripts:
            if script_body and script_body not in texts:
                texts.append(script_body)

        for text in texts:
            for sp, redacted, context in _scan_text(text, url):
                key = (sp.name, url)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_make_finding(sp, redacted, context, url))

        return findings
