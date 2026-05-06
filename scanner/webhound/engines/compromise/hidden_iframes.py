# WebHound — scanner/webhound/engines/compromise/hidden_iframes.py
# Passive detection of hidden or suspicious iframes.
#
# Safe-mode: reads pre-extracted PageArtifacts and optional raw HTML.
# No active probing, no JavaScript execution.

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "hidden_iframes"

_DISPLAY_NONE = re.compile(r"display\s*:\s*none", re.I)
_VISIBILITY_HIDDEN = re.compile(r"visibility\s*:\s*hidden", re.I)
_OPACITY_ZERO = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I)
_OFFSCREEN = re.compile(r"(?:top|left)\s*:\s*-\d{3,}", re.I)

_TRUSTED_IFRAME_DOMAINS: frozenset[str] = frozenset({
    "youtube.com", "youtu.be", "vimeo.com",
    "google.com", "maps.google.com",
    "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com",
    "docs.google.com", "drive.google.com",
    "player.vimeo.com", "w.soundcloud.com",
    "open.spotify.com",
})

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "icu",
    "pw", "buzz", "live", "online", "site", "space", "work",
})


def _is_hidden(tag: Tag) -> bool:
    style = tag.get("style", "")
    if isinstance(style, list):
        style = " ".join(style)

    if (_DISPLAY_NONE.search(style)
            or _VISIBILITY_HIDDEN.search(style)
            or _OPACITY_ZERO.search(style)
            or _OFFSCREEN.search(style)):
        return True

    width = tag.get("width", "")
    height = tag.get("height", "")
    if isinstance(width, list):
        width = width[0] if width else ""
    if isinstance(height, list):
        height = height[0] if height else ""

    try:
        if int(str(width).strip()) <= 1:
            return True
    except (ValueError, TypeError):
        pass
    try:
        if int(str(height).strip()) <= 1:
            return True
    except (ValueError, TypeError):
        pass

    return False


def _is_suspicious_src(src: str) -> bool:
    src_lower = src.lower()
    if src_lower.startswith(("javascript:", "data:")):
        return True
    tld = src_lower.split("//", 1)[-1].split("/")[0].rsplit(".", 1)[-1]
    return tld in _SUSPICIOUS_TLDS


def _is_trusted_src(src: str) -> bool:
    host = src.lower().split("//", 1)[-1].split("/")[0]
    return any(host == d or host.endswith(f".{d}") for d in _TRUSTED_IFRAME_DOMAINS)


class HiddenIframesEngine:
    """Passive detection of hidden or suspicious iframes.

    Requires ``html_body`` to be provided; returns an empty list if it is not.
    Parses raw HTML with BeautifulSoup and checks every ``<iframe>`` for:

    - CSS/size-based hiding (display:none, visibility:hidden, opacity:0,
      offscreen positioning, width/height <= 1px)
    - Suspicious ``src`` attributes (data:, javascript:, risky TLDs)

    A hidden iframe with a suspicious source is :attr:`Severity.CRITICAL`;
    a hidden iframe with an unknown/untrusted source is :attr:`Severity.HIGH`;
    a hidden iframe from a trusted domain is still reported at
    :attr:`Severity.MEDIUM` (legitimate but worth noting).

    Call ``analyze(artifacts, html_body=...)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        html_body: str | None = None,
    ) -> list[Finding]:
        if not html_body:
            return []

        soup = BeautifulSoup(html_body, "lxml")
        findings: list[Finding] = []

        for iframe in soup.find_all("iframe"):
            if not isinstance(iframe, Tag):
                continue
            findings.extend(self._check_iframe(iframe, artifacts))

        return findings

    def _check_iframe(self, iframe: Tag, artifacts: PageArtifacts) -> list[Finding]:
        src = iframe.get("src", "")
        if isinstance(src, list):
            src = src[0] if src else ""
        src = str(src).strip()

        hidden = _is_hidden(iframe)
        suspicious = bool(src) and _is_suspicious_src(src)
        trusted = bool(src) and _is_trusted_src(src)

        outer = str(iframe)[:200]

        if hidden and suspicious:
            return [Finding(
                title="Hidden iframe with suspicious source detected",
                description=(
                    f"A hidden <iframe> was found pointing to '{src or '(no src)'}'. "
                    "Hidden iframes with suspicious or data-URI sources are a "
                    "hallmark of drive-by download attacks and clickjacking payloads."
                ),
                severity=Severity.CRITICAL,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=outer,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"src": src, "hidden": True},
                )],
                confidence=0.9,
                remediation=(
                    "Remove the hidden iframe immediately. "
                    "Investigate server logs for unauthorized file modifications. "
                    "Implement a Content Security Policy with frame-src."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-1021", "CWE-494"],
                    nist_controls=["SI-3", "IR-4"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            )]

        if hidden and not trusted:
            return [Finding(
                title="Hidden iframe detected",
                description=(
                    f"A hidden <iframe>{' with src ' + src if src else ''} was found. "
                    "Hidden iframes may be used for clickjacking, malware delivery, "
                    "or tracking without user consent."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=outer,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"src": src, "hidden": True},
                )],
                confidence=0.8,
                remediation=(
                    "Review the purpose of this iframe. If not intentional, "
                    "remove it and audit the page for compromise. "
                    "Implement X-Frame-Options and CSP frame-src."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-1021"],
                    nist_controls=["SI-3"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            )]

        if hidden and trusted:
            return [Finding(
                title="Hidden iframe from known platform detected",
                description=(
                    f"A hidden <iframe> embedding '{src}' was found. "
                    "Although the source appears to be a known platform, "
                    "hidden iframes may violate user-consent expectations."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=outer,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"src": src, "hidden": True, "trusted": True},
                )],
                confidence=0.6,
                remediation=(
                    "Confirm this hidden embed is intentional and documented. "
                    "Consider whether it requires user consent under applicable "
                    "privacy regulations (GDPR, CCPA)."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-1021"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            )]

        return []
