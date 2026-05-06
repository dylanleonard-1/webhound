# WebHound — scanner/webhound/engines/javascript/third_party_domains.py
# Passive analysis of third-party domains referenced by a page.
#
# Safe-mode: reads pre-extracted PageArtifacts only.
# No DNS lookups, no HTTP fetches, no active probing.

from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "third_party_domains"

# TLDs frequently associated with free/disposable domains or abuse infrastructure.
_RISKY_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",   # Freenom free TLDs, high abuse rate
    "xyz", "top", "win", "date", "review", "racing", "stream",
    "download", "click", "link", "online", "site", "website",
    "cc", "pw", "su",
})

# Registered domains (domain.suffix) that are well-known CDNs or trusted platforms.
# Scripts from these domains are common and not flagged as suspicious.
_TRUSTED_DOMAINS: frozenset[str] = frozenset({
    "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "google.com",
    "cloudflare.com", "cloudflare.net",
    "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com",
    "jquery.com", "jquery.org",
    "cloudfront.net",
    "fastly.net", "fastly.com",
    "akamaized.net", "akamai.com", "akamaihd.net",
    "amazonaws.com", "aws.amazon.com",
    "facebook.net", "facebook.com",
    "twitter.com",
    "github.io", "github.com", "githubusercontent.com",
    "hotjar.com",
    "licdn.com",
    "intercomcdn.com",
    "stripe.com", "stripe.network",
    "paypal.com", "paypalobjects.com",
    "typekit.net", "adobe.com",
    "vimeo.com", "vimeocdn.com",
    "youtube.com", "ytimg.com",
    "twimg.com",
    "addthis.com",
    "disqus.com", "disquscdn.com",
})

# Heuristic: domain name with very few vowels looks machine-generated.
_VOWELS: frozenset[str] = frozenset("aeiouAEIOU")
_RANDOM_DOMAIN_MIN_LEN = 8
_RANDOM_DOMAIN_VOWEL_THRESHOLD = 0.12


class ThirdPartyDomainEngine:
    """Passive analysis of third-party resource domains referenced by a page.

    Checks external script src domains and external form action domains.
    Call ``analyze(artifacts)`` to receive a list of findings.
    Safe-mode: no network activity.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        page_host = urlparse(artifacts.url).hostname or ""

        findings.extend(
            self._check_script_domains(artifacts, page_host)
        )
        findings.extend(
            self._check_form_action_domains(artifacts, page_host)
        )

        return findings

    # ------------------------------------------------------------------
    # External script domains
    # ------------------------------------------------------------------

    def _check_script_domains(
        self, artifacts: PageArtifacts, page_host: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for script in artifacts.scripts:
            if not script.is_external or not script.src or not script.is_external_domain:
                continue
            host = urlparse(script.src).hostname or ""
            registered = _registered_domain(host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)

            if _is_trusted(registered):
                continue

            severity, label = _domain_risk(host, registered)
            ev = Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=f"External script from {host}: {script.src}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": host, "script_src": script.src},
            )
            findings.append(Finding(
                title=f"Third-party script loaded from {host} ({label})",
                description=(
                    f"A script is loaded from the third-party domain '{host}'. "
                    "Third-party scripts run with full page privileges. "
                    "A compromised or malicious third-party script can steal "
                    "credentials, exfiltrate data, or inject malicious content."
                ),
                severity=severity,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.8,
                remediation=(
                    "Audit all third-party scripts. Use Subresource Integrity (SRI) "
                    "hashes on <script> tags to detect tampering. "
                    "Host critical scripts on your own infrastructure where possible."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10", "SA-12"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": host},
            ))

        return findings

    # ------------------------------------------------------------------
    # External form action domains
    # ------------------------------------------------------------------

    def _check_form_action_domains(
        self, artifacts: PageArtifacts, page_host: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for form in artifacts.forms:
            if not form.action_url:
                continue
            action_host = urlparse(form.action_url).hostname or ""
            if not action_host or action_host == page_host:
                continue
            registered = _registered_domain(action_host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)

            ev = Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=(
                    f"Form action points to external domain '{action_host}': "
                    f"{form.action_url}"
                ),
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": action_host, "action_url": form.action_url},
            )
            findings.append(Finding(
                title=f"Form submits data to external domain: {action_host}",
                description=(
                    f"A form's action attribute points to '{action_host}', an "
                    "external domain. Form data (including credentials or PII) "
                    "submitted via this form is sent to a third party. "
                    "This may be intentional (payment provider) or indicate "
                    "form hijacking."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.75,
                remediation=(
                    "Verify the external form action is intentional and the "
                    "destination is a trusted service provider. "
                    "Ensure the form uses HTTPS and that the target is legitimate."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": action_host},
            ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registered_domain(hostname: str) -> str | None:
    """Return 'domain.suffix' (e.g., 'cloudflare.com') for a hostname."""
    if not hostname:
        return None
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _is_trusted(registered: str) -> bool:
    return registered in _TRUSTED_DOMAINS


def _looks_random(hostname: str) -> bool:
    """Heuristic: hostname with very few vowels is likely machine-generated."""
    ext = tldextract.extract(hostname)
    name = ext.domain
    if not name or len(name) < _RANDOM_DOMAIN_MIN_LEN:
        return False
    vowel_count = sum(1 for c in name if c in _VOWELS)
    return (vowel_count / len(name)) < _RANDOM_DOMAIN_VOWEL_THRESHOLD


def _domain_risk(hostname: str, registered: str) -> tuple[Severity, str]:
    """Return (severity, label) for a third-party domain based on risk indicators."""
    ext = tldextract.extract(hostname)
    tld = ext.suffix.lower() if ext.suffix else ""

    if tld in _RISKY_TLDS:
        return Severity.MEDIUM, "risky TLD"
    if _looks_random(hostname):
        return Severity.MEDIUM, "random-looking domain"
    return Severity.LOW, "unknown third party"
