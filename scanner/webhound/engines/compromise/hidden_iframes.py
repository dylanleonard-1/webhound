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
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "hidden_iframes"

_DISPLAY_NONE = re.compile(r"display\s*:\s*none", re.I)
_VISIBILITY_HIDDEN = re.compile(r"visibility\s*:\s*hidden", re.I)
_OPACITY_ZERO = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I)
_OFFSCREEN = re.compile(r"(?:top|left)\s*:\s*-\d{3,}", re.I)

# `<iframe srcdoc="…<script>…">` lets an attacker run arbitrary JS without
# loading anything external — bypasses CSP script-src whitelists in most
# configurations.
_SRCDOC_SCRIPT = re.compile(r"<script\b", re.I)

_TRUSTED_IFRAME_DOMAINS: frozenset[str] = frozenset({
    "youtube.com", "youtu.be", "vimeo.com", "youtube-nocookie.com",
    "google.com", "maps.google.com", "calendar.google.com",
    "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com",
    "docs.google.com", "drive.google.com",
    "player.vimeo.com", "w.soundcloud.com",
    "open.spotify.com", "embed.tiktok.com",
    "stripe.com", "js.stripe.com", "checkout.stripe.com",
    "paypal.com",
})

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "icu",
    "pw", "buzz", "live", "online", "site", "space", "work",
    "rest", "monster", "fit", "loan",
})

_FA: dict[str, FrameworkAlignment] = {
    "hidden_suspicious": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-1021", "CWE-494", "CWE-829"],
        nist_controls=["SI-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.0,
        pci_dss=["6.4.3", "11.6.1"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(1)(ii)(D)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "hidden_unknown": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-1021"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hidden_trusted": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-1021"],
        nist_controls=["AR-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=[],
        iso_27001=["A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "sandbox_bypass": FrameworkAlignment(
        owasp_top10=["A05:2021", "A08:2021"],
        cwe_ids=["CWE-1021", "CWE-732"],
        nist_controls=["AC-3", "SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.5", "A.8.25"],
        soc2=["CC6.1", "CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "srcdoc_script": FrameworkAlignment(
        owasp_top10=["A08:2021", "A03:2021"],
        cwe_ids=["CWE-79", "CWE-1021"],
        nist_controls=["SI-3", "SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.0,
        pci_dss=["6.2.4", "6.4.3"],
        iso_27001=["A.8.25", "A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
}


def _is_hidden(tag: Tag) -> bool:
    style = tag.get("style", "")
    if isinstance(style, list):
        style = " ".join(style)
    if (_DISPLAY_NONE.search(style) or _VISIBILITY_HIDDEN.search(style)
            or _OPACITY_ZERO.search(style) or _OFFSCREEN.search(style)):
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


def _sandbox_tokens(tag: Tag) -> set[str]:
    sb = tag.get("sandbox")
    if sb is None:
        return set()
    if isinstance(sb, list):
        sb = " ".join(sb)
    return {t.strip().lower() for t in str(sb).split() if t.strip()}


class HiddenIframesEngine:
    """Passive detection of hidden or otherwise risky iframes.

    Findings:
    - Hidden iframe + suspicious src (data:, javascript:, risky TLD) →
      CRITICAL, drive-by / clickjacking payload signature.
    - Hidden iframe + unknown src → HIGH.
    - Hidden iframe + trusted vendor src → LOW (informational; legitimate
      but still worth surfacing for GDPR/CCPA consent review).
    - Iframe `sandbox` attribute set to `allow-scripts allow-same-origin`
      → HIGH, sandbox-escape combo that defeats the whole point.
    - Iframe `srcdoc` containing a `<script>` tag → HIGH, inline JS
      execution that bypasses script-src CSP.
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
        outer = str(iframe)[:200]
        results: list[Finding] = []

        hidden = _is_hidden(iframe)
        suspicious = bool(src) and _is_suspicious_src(src)
        trusted = bool(src) and _is_trusted_src(src)

        if hidden and suspicious:
            results.append(Finding(
                title="Hidden iframe with suspicious source",
                description=(
                    f"A hidden `<iframe>` was found pointing to "
                    f"'{src or '(no src)'}'. The combination of "
                    "off-screen / zero-size / display:none rendering AND a "
                    "src that resolves to a data URI, a `javascript:` URL, "
                    "or a domain on a cheap/throwaway TLD is the textbook "
                    "shape of a drive-by-download payload or a clickjacking "
                    "overlay. Legitimate code doesn't ship invisible "
                    "iframes pointing at unfamiliar hosts."
                ),
                severity=Severity.CRITICAL,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=outer,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"src": src, "hidden": True, "suspicious_src": True},
                )],
                confidence=0.92,
                remediation=(
                    "Treat as a compromise: remove the iframe, snapshot the "
                    "page HTML for forensics, audit your CMS for unauthorised "
                    "template edits, and rotate credentials. Long-term, "
                    "enforce `frame-src` and `frame-ancestors` in your "
                    "Content Security Policy so injected iframes either "
                    "fail to load or fail to frame the page."
                ),
                framework=_FA["hidden_suspicious"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            ))
        elif hidden and not trusted:
            results.append(Finding(
                title="Hidden iframe with unknown source",
                description=(
                    f"A hidden `<iframe>{(' with src ' + src) if src else ''}` "
                    "was found. The iframe is rendered off-screen / "
                    "zero-size / display:none, which makes it invisible to "
                    "the user. Hidden iframes are sometimes legitimate "
                    "(tracking pixels, ad-network handshakes) but are also "
                    "the default carrier for clickjacking and drive-by "
                    "malware. Confirm the source is something you control."
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
                    "Audit the iframe's source against your inventory of "
                    "approved third-party domains. If it's not on the list, "
                    "remove it and check the page template for unauthorised "
                    "edits. Set `frame-src` in CSP to a closed allowlist so "
                    "rogue iframes fail to load."
                ),
                framework=_FA["hidden_unknown"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            ))
        elif hidden and trusted:
            results.append(Finding(
                title=f"Hidden iframe from a known platform ({_host_of(src)})",
                description=(
                    f"A hidden `<iframe>` embeds '{src}'. The source is on "
                    "the trusted-platforms list (YouTube, Stripe, Google "
                    "Maps, etc.), so this isn't a security incident — but "
                    "a hidden embed from a third party still loads the "
                    "vendor's JavaScript and trackers without the user "
                    "having opted in. Worth a privacy/consent review under "
                    "GDPR and CCPA."
                ),
                severity=Severity.LOW,
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
                    "Confirm the hidden embed is intentional and that your "
                    "privacy policy lists the vendor. Consider deferring "
                    "the iframe until after consent for visitors in GDPR/"
                    "CCPA jurisdictions."
                ),
                framework=_FA["hidden_trusted"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "iframe_src": src},
            ))

        # Sandbox-bypass: `allow-scripts allow-same-origin` together let the
        # framed page escape the sandbox and act on the parent origin.
        tokens = _sandbox_tokens(iframe)
        if tokens and {"allow-scripts", "allow-same-origin"}.issubset(tokens):
            results.append(Finding(
                title="Iframe sandbox includes both allow-scripts and allow-same-origin",
                description=(
                    "The iframe carries `sandbox=\"… allow-scripts "
                    "allow-same-origin …\"`. That combination defeats the "
                    "sandbox: scripts inside the iframe can call back into "
                    "the parent origin (same-origin policy treats them as "
                    "trusted) and modify cookies, localStorage, and DOM. "
                    "The MDN docs explicitly warn against this exact "
                    "combination."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=outer,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"sandbox_tokens": sorted(tokens)},
                )],
                confidence=0.95,
                remediation=(
                    "Drop one of the two flags. If you need scripts inside "
                    "the iframe, serve the framed content from a separate "
                    "origin so `allow-same-origin` isn't required. If you "
                    "need same-origin DOM access, omit `allow-scripts` and "
                    "use `postMessage` for the cross-frame communication."
                ),
                framework=_FA["sandbox_bypass"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "sandbox": sorted(tokens)},
            ))

        # srcdoc with inline script — runs in the iframe origin without
        # touching any script-src whitelist.
        srcdoc = iframe.get("srcdoc")
        if isinstance(srcdoc, list):
            srcdoc = " ".join(srcdoc)
        if srcdoc and _SRCDOC_SCRIPT.search(str(srcdoc)):
            results.append(Finding(
                title="Iframe srcdoc contains inline <script>",
                description=(
                    "The iframe uses the `srcdoc` attribute and the inline "
                    "HTML inside it includes a `<script>` tag. `srcdoc` "
                    "creates a same-origin frame whose content runs without "
                    "fetching any external URL — which means the parent "
                    "page's `script-src` directive doesn't apply to it. "
                    "Stored XSS that lands in a `srcdoc` value can run "
                    "arbitrary code even on sites with a strict CSP."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<iframe srcdoc=\"{str(srcdoc)[:200]}…\">",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                )],
                confidence=0.85,
                remediation=(
                    "Avoid `srcdoc` with inline scripts. If you must embed "
                    "trusted HTML, render it server-side and serve it from "
                    "a separate origin via `src`, then govern that origin "
                    "with its own CSP. If the `srcdoc` value comes from "
                    "user input, treat this as a stored-XSS vulnerability."
                ),
                framework=_FA["srcdoc_script"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url},
            ))

        return results


def _host_of(url: str) -> str:
    return (url.lower().split("//", 1)[-1] if "//" in url else url.lower()
            ).split("/")[0]
