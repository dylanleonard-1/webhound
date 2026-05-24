# WebHound — scanner/webhound/engines/threat_intel/external_domains.py
# Threat-intel-driven assessment of every external domain the page touches.
#
# This is the scanner-engine wrapper around the local threat_intel package.
# It collects every external host the page references (script srcs, stylesheet
# links, iframe sources, form actions, image sources), classifies each through
# the local DomainClassifier, and emits findings for the high-risk ones.
#
# Safe-mode: reads pre-extracted PageArtifacts only. The DomainClassifier itself
# is offline — pure heuristics over static lists, no DNS, no HTTP, no external
# API calls. External providers (URLhaus, VirusTotal) are pluggable but
# disabled by default; they have their own offline-safe stub clients.

from __future__ import annotations

from urllib.parse import urlparse

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity
from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassification,
    DomainClassifier,
)

_ENGINE = "threat_intel"


_FA: dict[str, FrameworkAlignment] = {
    "inventory": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829", "CWE-1395"],
        nist_controls=["CM-8", "SR-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=["6.4.3", "12.8.5"],
        iso_27001=["A.5.19", "A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "malicious_indicator": FrameworkAlignment(
        owasp_top10=["A08:2021", "A05:2021"],
        cwe_ids=["CWE-829", "CWE-506"],
        nist_controls=["SI-3", "SR-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cvss_score=10.0,
        pci_dss=["6.4.3", "11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.5.30"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(1)(ii)(D)", "164.308(a)(6)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "risky": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829"],
        nist_controls=["SI-3", "SR-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "suspicious": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "url_shortener": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "punycode": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-1007", "CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
}


def _hostname(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _gather_external_hosts(artifacts: PageArtifacts) -> dict[str, set[str]]:
    """Return {hostname: set_of_source_url_categories}.

    Categories: 'script', 'stylesheet', 'iframe', 'image', 'form_action',
    'link', 'js_request', 'css_import'.
    """
    page_host = _hostname(artifacts.url)
    by_host: dict[str, set[str]] = {}

    def _add(url: str, kind: str) -> None:
        host = _hostname(url)
        if not host or host == page_host:
            return
        by_host.setdefault(host, set()).add(kind)

    for u in artifacts.external_script_urls:
        _add(u, "script")
    for u in artifacts.external_stylesheet_urls:
        _add(u, "stylesheet")
    for u in artifacts.external_image_urls:
        _add(u, "image")
    for u in artifacts.inline_js_request_urls:
        _add(u, "js_request")
    for u in artifacts.inline_css_import_urls:
        _add(u, "css_import")
    for u in artifacts.external_links:
        _add(u, "link")
    for f in artifacts.forms:
        if f.action_url:
            _add(f.action_url, "form_action")
    for iframe in artifacts.iframes:
        if iframe.src_url:
            _add(iframe.src_url, "iframe")
    return by_host


class ThreatIntelEngine:
    """Threat-intelligence assessment of every external domain on the page.

    Wraps the local :class:`DomainClassifier` and emits findings for each
    high-risk external host the page references. Zero external API calls
    in default offline mode — uses only the bundled static lists and
    heuristics. Designed to complement (not replace) the per-context
    checks in javascript / third_party_domains / suspicious_redirects:
    those engines look at where a script/link/iframe is used, while this
    engine consolidates the verdict on each unique external host.
    """

    NAME = _ENGINE

    def __init__(self, classifier: DomainClassifier | None = None) -> None:
        self._classifier = classifier or DomainClassifier()

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        hosts = _gather_external_hosts(artifacts)
        if not hosts:
            return []

        page_url = artifacts.url
        findings: list[Finding] = []

        # Classify every external host once.
        classifications: list[tuple[str, DomainClassification, set[str]]] = []
        for host, kinds in hosts.items():
            cls = self._classifier.classify(host)
            classifications.append((host, cls, kinds))

        # ---- Inventory finding (INFO) ----
        by_tier: dict[DomainClass, int] = {}
        for _, cls, _ in classifications:
            by_tier[cls.classification] = by_tier.get(cls.classification, 0) + 1
        findings.append(self._inventory_finding(page_url, classifications, by_tier))

        # ---- Per-host high-risk findings ----
        for host, cls, kinds in classifications:
            tier = cls.classification
            if tier == DomainClass.MALICIOUS_INDICATOR:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.CRITICAL,
                    framework_key="malicious_indicator",
                ))
            elif tier == DomainClass.RISKY:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.HIGH,
                    framework_key="risky",
                ))
            elif tier == DomainClass.SUSPICIOUS:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.MEDIUM,
                    framework_key="suspicious",
                ))
            else:
                continue

        # ---- Special-case findings driven by individual signals ----
        for host, cls, kinds in classifications:
            if cls.is_url_shortener:
                findings.append(self._shortener_finding(host, cls, kinds, page_url))
            if cls.is_punycode:
                findings.append(self._punycode_finding(host, cls, kinds, page_url))

        return findings

    # ------------------------------------------------------------------

    def _inventory_finding(self, page_url: str,
                           classifications: list[tuple[str, DomainClassification, set[str]]],
                           by_tier: dict[DomainClass, int]) -> Finding:
        host_lines = []
        for host, cls, kinds in classifications[:30]:
            kinds_str = ",".join(sorted(kinds))
            host_lines.append(
                f"{host:<48s} [{cls.classification.value:<22s}] "
                f"score={cls.score:.1f} kinds={kinds_str}"
            )
        if len(classifications) > 30:
            host_lines.append(f"… (+{len(classifications) - 30} more hosts)")
        return Finding(
            title=f"Third-party domain inventory: {len(classifications)} external host(s)",
            description=(
                f"The page references {len(classifications)} external domains. "
                + ", ".join(f"{cnt} {tier.value}" for tier, cnt in by_tier.items())
                + ". Modern websites typically depend on 10-50 external "
                "domains (analytics, fonts, CDNs, payment processors, "
                "chat widgets, ad networks). Each one is a supply-chain "
                "trust decision: if that domain's vendor is compromised, "
                "anything they ship into the page runs with the page's "
                "origin authority. This finding is informational — the "
                "individual high-risk hosts get their own findings below."
            ),
            severity=Severity.INFO,
            category=FindingCategory.TECHNOLOGY,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content="\n".join(host_lines),
                location=page_url,
                source_engine=_ENGINE,
                extra={"external_host_count": len(classifications),
                       "tier_counts": {t.value: c for t, c in by_tier.items()}},
            )],
            confidence=0.95,
            remediation=(
                "Maintain a written third-party vendor inventory listing "
                "every external domain, its purpose, and its security "
                "posture (SOC 2 / ISO 27001 attestation, breach history). "
                "Review quarterly and remove vendors no longer needed. "
                "Enforce a strict Content Security Policy that lists every "
                "vendor host explicitly — this stops a compromised vendor "
                "from being able to load arbitrary additional code."
            ),
            framework=_FA["inventory"],
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "host_count": len(classifications)},
        )

    def _host_finding(self, host: str, cls: DomainClassification,
                      kinds: set[str], page_url: str,
                      severity: Severity, framework_key: str) -> Finding:
        kinds_str = ", ".join(sorted(kinds))
        signal_lines = "\n".join(f"  • {s}" for s in cls.signals)
        title_prefix = {
            "malicious_indicator": "Likely malicious",
            "risky": "High-risk",
            "suspicious": "Suspicious",
        }[framework_key]
        return Finding(
            title=f"{title_prefix} third-party host: {host}",
            description=(
                f"The page loads resources from `{host}` "
                f"(used as: {kinds_str}). The local threat-intelligence "
                f"classifier scored it {cls.score:.1f}/10.0 — "
                f"`{cls.classification.value}`. Multiple converging signals: "
                "cheap/abuse-prone TLD, brand-lookalike, machine-generated "
                "label, punycode/IDN, URL shortener, or suspicious-keyword "
                "label, depending on which fired. "
                f"Signals matched on this host:\n{signal_lines}"
            ),
            severity=severity,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content=(
                    f"Host: {host}\n"
                    f"Classification: {cls.classification.value} "
                    f"(score {cls.score:.1f}/10.0, confidence {cls.confidence:.0%})\n"
                    f"Registered: {cls.registerable_domain or '?'}\n"
                    f"TLD: .{cls.tld or '?'}\n"
                    f"Used as: {kinds_str}\n"
                    f"Signals:\n{signal_lines}"
                ),
                location=page_url,
                source_engine=_ENGINE,
                extra={
                    "host": host,
                    "classification": cls.classification.value,
                    "score": cls.score,
                    "signals": cls.signals,
                    "kinds": sorted(kinds),
                },
            )],
            confidence=cls.confidence,
            remediation=(
                "Determine whether `" + host + "` is a known, intentional "
                "vendor. If yes, document it in your third-party inventory "
                "and add the host to your CSP allowlist. If you can't "
                "account for it, treat the page as potentially compromised: "
                "snapshot the HTML, audit recent template/CMS changes, "
                "and rotate credentials. Look for similar-named hosts "
                "across the rest of the site — a single foothold usually "
                "leaves traces in multiple pages."
            ),
            framework=_FA[framework_key],
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "host": host,
                      "classification": cls.classification.value,
                      "score": cls.score, "kinds": sorted(kinds),
                      "signals": cls.signals},
        )

    def _shortener_finding(self, host: str, cls: DomainClassification,
                           kinds: set[str], page_url: str) -> Finding:
        kinds_str = ", ".join(sorted(kinds))
        return Finding(
            title=f"URL shortener as third-party host: {host}",
            description=(
                f"The page references `{host}`, a URL-shortening service "
                f"(used as: {kinds_str}). Shorteners hide the final "
                "destination from both static analysis and the user. "
                "On a legitimate site they're sometimes used for tracking; "
                "in compromise scenarios they're the standard way to "
                "redirect visitors through an attacker-controlled hop. "
                "When you can't tell which case applies, treat it as a "
                "supply-chain trust unknown."
            ),
            severity=Severity.LOW,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content=f"Host: {host}\nUsed as: {kinds_str}",
                location=page_url,
                source_engine=_ENGINE,
                extra={"host": host, "kinds": sorted(kinds)},
            )],
            confidence=0.85,
            remediation=(
                "Replace shortener URLs with the direct destination so "
                "scanners, security filters, and users can see where the "
                "link leads. If shorteners are required for click "
                "tracking, run your own first-party shortener under your "
                "domain rather than depending on a third-party service."
            ),
            framework=_FA["url_shortener"],
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "host": host, "kinds": sorted(kinds)},
        )

    def _punycode_finding(self, host: str, cls: DomainClassification,
                          kinds: set[str], page_url: str) -> Finding:
        kinds_str = ", ".join(sorted(kinds))
        return Finding(
            title=f"Punycode (IDN) domain referenced: {host}",
            description=(
                f"The page references `{host}`, an internationalised "
                "domain name (one or more labels begin with `xn--`). IDN "
                "domains are legitimate for non-Latin scripts, but they "
                "are also the foundation of homoglyph attacks: an "
                "attacker registers `xn--pple-43d.com` which the browser "
                "renders as `аpple.com` (Cyrillic 'а' instead of Latin "
                "'a'). The character difference is invisible to users; "
                "the registered domain is not affiliated with Apple at "
                "all. Worth a manual look at what this host is actually "
                "supposed to be."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content=f"Host: {host}\nUsed as: {kinds_str}",
                location=page_url,
                source_engine=_ENGINE,
                extra={"host": host, "kinds": sorted(kinds),
                       "is_punycode": True},
            )],
            confidence=0.7,
            remediation=(
                "Decode the punycode (`idna.decode` in Python, `punycode` "
                "Node module) to see what the rendered domain looks like. "
                "If the rendering resembles a known brand but the "
                "registered owner doesn't match, treat as compromise. "
                "For legitimate non-Latin sites, document the IDN in "
                "your vendor inventory so it doesn't trip alarms again."
            ),
            framework=_FA["punycode"],
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "host": host, "kinds": sorted(kinds)},
        )
