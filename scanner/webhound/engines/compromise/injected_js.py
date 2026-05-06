# WebHound — scanner/webhound/engines/compromise/injected_js.py
# Passive detection of injected/malicious JavaScript patterns.
#
# Safe-mode: reads pre-extracted PageArtifacts only.
# No JavaScript execution, no exploitation.

from __future__ import annotations

import re
from urllib.parse import urlparse

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "injected_js"

_PAYMENT_TERMS = re.compile(
    r"\b(?:card_?number|cc_?num(?:ber)?|cvv|cvc2?|expir(?:y|ation)|"
    r"cardhold(?:er)?|pan\b|track_?data|payment_?data|"
    r"credit_?card|debit_?card)\b",
    re.I,
)

_SEND_TERMS = re.compile(
    r"\b(?:fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|"
    r"\.send\s*\(|\.post\s*\(|\.ajax\s*\()",
    re.I,
)

_DYNAMIC_SCRIPT_INJECT = re.compile(
    r"createElement\s*\(\s*['\"]script['\"]\s*\)",
    re.I,
)

_BEACON_PATTERNS = re.compile(
    r"new\s+Image\s*\(\s*\)\s*\.src\s*=|"
    r"navigator\.sendBeacon\s*\(|"
    r"\bXMLHttpRequest\b.*?\bsend\b",
    re.I,
)

_SKIMMER_KEYWORDS = re.compile(
    r"\b(?:formjack(?:ing)?|magecart|skimmer|keylog(?:ger)?|"
    r"exfiltrat(?:e|ion)|cc_?harvest|card_?steal|card_?grab)\b",
    re.I,
)

_EXTERNAL_URL_IN_SCRIPT = re.compile(
    r"['\"]https?://([a-zA-Z0-9._-]{4,})/",
    re.I,
)

_RISKY_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "icu",
    "pw", "buzz", "live", "online", "site", "space", "work",
})


class InjectedJsEngine:
    """Passive detection of injected/malicious JavaScript.

    Scans inline script content (from ``PageArtifacts.inline_scripts``) for
    patterns associated with payment skimming, dynamic script injection,
    data exfiltration beacons, and known skimmer keywords.

    All checks are regex-only; no JavaScript is executed.

    Call ``analyze(artifacts)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        html_body: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        scripts = artifacts.inline_scripts

        for idx, script in enumerate(scripts):
            if not script:
                continue
            findings.extend(self._check_payment_harvest(script, idx, artifacts))
            findings.extend(self._check_dynamic_inject(script, idx, artifacts))
            findings.extend(self._check_beacon_exfil(script, idx, artifacts))
            findings.extend(self._check_skimmer_keywords(script, idx, artifacts))

        findings.extend(self._check_suspicious_external_scripts(artifacts))
        return findings

    # ------------------------------------------------------------------

    def _check_payment_harvest(
        self,
        script: str,
        idx: int,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        if not (_PAYMENT_TERMS.search(script) and _SEND_TERMS.search(script)):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Potential payment card skimmer detected",
            description=(
                "An inline script references payment card field names "
                "(card number, CVV, expiry) combined with data-transmission "
                "functions (fetch, XMLHttpRequest, sendBeacon). This pattern "
                "is characteristic of Magecart-style payment skimmers."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.8,
            remediation=(
                "Audit all inline scripts and third-party script sources. "
                "Implement a Content Security Policy (CSP) with script-src. "
                "Consider Subresource Integrity (SRI) on all external scripts."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021"],
                cwe_ids=["CWE-506", "CWE-494"],
                nist_controls=["SI-3", "SI-7"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_dynamic_inject(
        self,
        script: str,
        idx: int,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        if not _DYNAMIC_SCRIPT_INJECT.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Dynamic script injection detected",
            description=(
                "An inline script dynamically creates a <script> element "
                "via document.createElement('script'). Attackers use this "
                "technique to load malicious scripts that evade static CSP checks."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.7,
            remediation=(
                "Review this script to confirm the injected source is trusted. "
                "Use a strict Content Security Policy. "
                "Implement Subresource Integrity for all dynamically loaded scripts."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021"],
                cwe_ids=["CWE-494"],
                nist_controls=["SI-3"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_beacon_exfil(
        self,
        script: str,
        idx: int,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        if not _BEACON_PATTERNS.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Data exfiltration beacon pattern detected",
            description=(
                "An inline script contains patterns associated with data "
                "exfiltration beacons: new Image().src=, navigator.sendBeacon(), "
                "or XMLHttpRequest.send(). These techniques are used to silently "
                "transmit captured data to attacker-controlled servers."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.65,
            remediation=(
                "Audit this script for data harvesting. Implement CSP with "
                "connect-src and img-src directives to restrict beacon destinations."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021"],
                cwe_ids=["CWE-200", "CWE-359"],
                nist_controls=["SI-3", "SI-12"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_skimmer_keywords(
        self,
        script: str,
        idx: int,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        m = _SKIMMER_KEYWORDS.search(script)
        if not m:
            return []
        snippet = _snippet(script, around=m.start())
        return [Finding(
            title="Known skimmer/malware keyword detected in script",
            description=(
                f"An inline script contains the keyword '{m.group()}', which is "
                "associated with known web skimmer toolkits (Magecart, formjacking). "
                "This may indicate a compromised supply chain or injected malware."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx, "keyword": m.group()},
            )],
            confidence=0.9,
            remediation=(
                "Immediately audit all inline and third-party scripts. "
                "Consider the site potentially compromised and investigate "
                "server-side access logs for unauthorized modifications."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021"],
                cwe_ids=["CWE-506"],
                nist_controls=["SI-3", "IR-4"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_suspicious_external_scripts(
        self,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for src in artifacts.external_script_urls:
            if not src.startswith("http"):
                continue
            try:
                domain = urlparse(src).netloc.lower()
            except Exception:
                continue
            if not domain:
                continue
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            if tld in _RISKY_TLDS:
                findings.append(Finding(
                    title="External script from suspicious TLD",
                    description=(
                        f"A script is loaded from '{src}', which uses the "
                        f"'{tld}' TLD commonly associated with free/disposable "
                        "domains used in malware campaigns."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.COMPROMISE,
                    evidence=[Evidence(
                        evidence_type=EvidenceType.JAVASCRIPT,
                        content=f"Script src: {src}",
                        location=artifacts.url,
                        source_engine=_ENGINE,
                    )],
                    confidence=0.75,
                    remediation=(
                        "Verify the legitimacy of this script source. "
                        "If not intentional, remove and investigate for compromise."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A08:2021"],
                        cwe_ids=["CWE-829"],
                        nist_controls=["SI-3"],
                    ),
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url, "script_src": src},
                ))
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snippet(text: str, around: int = 0, length: int = 150) -> str:
    start = max(0, around - length // 2)
    return text[start: start + length].replace("\n", " ").strip()
