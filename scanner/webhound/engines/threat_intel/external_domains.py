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
from webhound.threat_intel.enrichment_service import (
    EnrichmentResult,
    EnrichmentService,
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

    def __init__(
        self,
        classifier: DomainClassifier | None = None,
        enrichment_service: EnrichmentService | None = None,
    ) -> None:
        self._classifier = classifier or DomainClassifier()
        self._enrichment = enrichment_service

    async def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        hosts = _gather_external_hosts(artifacts)
        if not hosts:
            return []

        page_url = artifacts.url
        findings: list[Finding] = []

        # Local classification first (instant, offline).
        classifications: list[tuple[str, DomainClassification, set[str],
                                     EnrichmentResult | None]] = []
        for host, kinds in hosts.items():
            cls = self._classifier.classify(host)
            classifications.append((host, cls, kinds, None))

        # If an enrichment service with providers is registered, call out
        # to each provider in parallel and merge verdicts. Each provider
        # has its own rate-limiter and per-instance cache so a 50-host page
        # is safe on the VT free tier (4 req/min, 500/day).
        if self._enrichment and self._enrichment.has_external_providers:
            enriched = await self._run_enrichment(
                [(h, cls, kinds) for h, cls, kinds, _ in classifications]
            )
            classifications = enriched

        # ---- Inventory finding (INFO) ----
        by_tier: dict[DomainClass, int] = {}
        for _, cls, _, enr in classifications:
            final = (enr.final_classification if enr else cls.classification)
            by_tier[final] = by_tier.get(final, 0) + 1
        findings.append(self._inventory_finding(page_url, classifications, by_tier))

        # ---- Per-host high-risk findings ----
        for host, cls, kinds, enr in classifications:
            # Use the merged classification if external providers ran.
            tier = enr.final_classification if enr else cls.classification
            if tier == DomainClass.MALICIOUS_INDICATOR:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.CRITICAL,
                    framework_key="malicious_indicator",
                    enrichment=enr,
                ))
            elif tier == DomainClass.RISKY:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.HIGH,
                    framework_key="risky",
                    enrichment=enr,
                ))
            elif tier == DomainClass.SUSPICIOUS:
                findings.append(self._host_finding(
                    host, cls, kinds, page_url,
                    severity=Severity.MEDIUM,
                    framework_key="suspicious",
                    enrichment=enr,
                ))
            else:
                continue

        # ---- Special-case findings driven by individual signals ----
        for host, cls, kinds, _ in classifications:
            if cls.is_url_shortener:
                findings.append(self._shortener_finding(host, cls, kinds, page_url))
            if cls.is_punycode:
                findings.append(self._punycode_finding(host, cls, kinds, page_url))

        return findings

    # ------------------------------------------------------------------
    # Scan-wide inventory pass (Phase-3 audit)
    # ------------------------------------------------------------------

    async def analyze_inventory(
        self,
        inventory,            # dict[str, HostInventoryEntry]
        *,
        already_classified_hosts: set[str] | None = None,
    ) -> list[Finding]:
        """Classify a scan-wide aggregated host inventory in one pass.

        The orchestrator gathers `PageHostContribution` objects during the
        crawl and folds them through ``aggregate_host_inventory`` into a
        ``{hostname: HostInventoryEntry}`` map. That map covers *every*
        external host the scan touched — including hosts discovered via
        JavaScript URL parsing or future Playwright network capture —
        rather than only the ones a single page's static HTML referenced.

        This method classifies each unique host exactly once, emits at
        most one finding per host, and uses each host's
        ``first_seen_page`` as the evidence location (with ``affected_pages``
        / ``sample_urls`` in metadata for backlinks). Hosts in
        ``already_classified_hosts`` are skipped so the per-page pass and
        the scan-wide pass don't double-emit for the same host.

        Returns ``[]`` if the inventory is empty.
        """
        if not inventory:
            return []
        already = already_classified_hosts or set()

        # Local classification first (instant, offline).
        items: list[tuple[str, DomainClassification, "HostInventoryEntry"]] = []  # noqa: F821
        for host, entry in inventory.items():
            if host in already:
                continue
            items.append((host, self._classifier.classify(host), entry))
        if not items:
            return []

        # Run external providers in parallel where available. The same
        # rate-limiter + cache the per-page path uses applies here, so a
        # 200-host inventory won't blow the VT free-tier quota in one shot.
        enriched: list[tuple[str, DomainClassification, "HostInventoryEntry",  # noqa: F821
                              EnrichmentResult | None]]
        if self._enrichment and self._enrichment.has_external_providers:
            import asyncio
            coros = [self._enrichment.enrich_domain(h) for h, _, _ in items]
            enrich_results = await asyncio.gather(*coros, return_exceptions=True)
            enriched = []
            for (host, cls, entry), enr in zip(items, enrich_results):
                enriched.append((
                    host, cls, entry,
                    enr if isinstance(enr, EnrichmentResult) else None,
                ))
        else:
            enriched = [(h, c, e, None) for h, c, e in items]

        findings: list[Finding] = []
        for host, cls, entry, enr in enriched:
            tier = enr.final_classification if enr else cls.classification
            # Only emit findings for non-benign tiers — the scan-wide
            # path skips per-host "informational" findings to avoid
            # exploding the dashboard with one entry per CDN.
            if tier == DomainClass.MALICIOUS_INDICATOR:
                findings.append(self._inventory_host_finding(
                    host, cls, entry, severity=Severity.CRITICAL,
                    framework_key="malicious_indicator", enrichment=enr,
                ))
            elif tier == DomainClass.RISKY:
                findings.append(self._inventory_host_finding(
                    host, cls, entry, severity=Severity.HIGH,
                    framework_key="risky", enrichment=enr,
                ))
            elif tier == DomainClass.SUSPICIOUS:
                findings.append(self._inventory_host_finding(
                    host, cls, entry, severity=Severity.MEDIUM,
                    framework_key="suspicious", enrichment=enr,
                ))
            # Shortener / punycode are scored as their own signals
            # regardless of overall tier — these patterns are noteworthy
            # even on otherwise-benign hosts.
            if cls.is_url_shortener:
                findings.append(self._inventory_special_finding(
                    host, cls, entry, kind="shortener",
                ))
            if cls.is_punycode:
                findings.append(self._inventory_special_finding(
                    host, cls, entry, kind="punycode",
                ))
        return findings

    def _inventory_host_finding(
        self, host: str, cls: DomainClassification, entry,  # HostInventoryEntry
        *, severity: Severity, framework_key: str,
        enrichment: EnrichmentResult | None = None,
    ) -> Finding:
        """Per-host finding from the scan-wide inventory pass. Differs from
        ``_host_finding`` in three ways:
          * evidence location is the host's ``first_seen_page``, so the
            finding ties back to a real URL even if the host was only
            discovered through scan-wide JS analysis;
          * metadata records all ``sample_urls`` + the full ``kinds`` set so
            the dashboard can render a "found on N requests" backlink;
          * the source label says "scan-wide inventory" explicitly so the
            UI can render a different badge from per-page detections.
        """
        kinds_str = ", ".join(sorted(entry.kinds))
        signal_lines = "\n".join(f"  • {s}" for s in cls.signals)
        title_prefix = {
            "malicious_indicator": "Likely malicious",
            "risky": "High-risk",
            "suspicious": "Suspicious",
        }[framework_key]
        page = entry.first_seen_page or ""
        return Finding(
            title=f"{title_prefix} third-party host: {host}",
            description=(
                f"The scan's aggregated third-party inventory identified "
                f"`{host}` as {framework_key}. It was first seen on "
                f"`{page or '<unknown page>'}` and referenced as: "
                f"{kinds_str}. Local threat-intel classifier scored "
                f"{cls.score:.1f}/10.0 — `{cls.classification.value}`. "
                f"Signals matched:\n{signal_lines}"
            ),
            severity=severity,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content=(
                    f"Host: {host}\n"
                    f"First seen on: {page}\n"
                    f"Referenced as: {kinds_str}\n"
                    f"Sample URLs (capped):\n  "
                    + "\n  ".join(entry.sample_urls or [])
                    + "\n"
                    f"Local classification: {cls.classification.value} "
                    f"(score {cls.score:.1f}/10.0, confidence {cls.confidence:.0%})\n"
                    f"Registered: {cls.registerable_domain or '?'}\n"
                    f"Signals:\n{signal_lines}"
                    + _format_enrichment(enrichment)
                ),
                location=page,
                source_engine=_ENGINE,
                extra={
                    "host": host,
                    "classification": cls.classification.value,
                    "score": cls.score,
                    "signals": cls.signals,
                    "kinds": sorted(entry.kinds),
                    "sample_urls": list(entry.sample_urls or []),
                    "discovery": "scan_wide_inventory",
                    **_enrichment_extras(enrichment),
                },
            )],
            confidence=cls.confidence,
            remediation=(
                "Determine whether `" + host + "` is a known, intentional "
                "vendor. If not, treat as supply-chain anomaly: snapshot "
                "the pages that reference it, audit recent template / "
                "vendor / CMS changes, and rotate credentials served from "
                "any affected page."
            ),
            framework=_FA[framework_key],
            scanner_engine=_ENGINE,
            tags=["scan_wide", "inventory"],
            metadata={
                "host": host,
                "classification": cls.classification.value,
                "score": cls.score,
                "kinds": sorted(entry.kinds),
                "signals": cls.signals,
                "first_seen_page": page,
                "sample_urls": list(entry.sample_urls or []),
                "discovery": "scan_wide_inventory",
            },
        )

    def _inventory_special_finding(
        self, host: str, cls: DomainClassification, entry,  # HostInventoryEntry
        *, kind: str,
    ) -> Finding:
        """Scan-wide variant of ``_shortener_finding`` / ``_punycode_finding``
        — surfaces these patterns with first_seen_page provenance even
        when the host wasn't classified as risky overall."""
        page = entry.first_seen_page or ""
        kinds_str = ", ".join(sorted(entry.kinds))
        if kind == "shortener":
            title = f"URL shortener as third-party host: {host}"
            severity = Severity.LOW
            confidence = 0.85
            description = (
                f"The scan's aggregated inventory references `{host}`, a "
                f"URL-shortening service (used as: {kinds_str}). "
                "Shorteners hide the final destination from static "
                "analysis and from the user."
            )
            fa_key = "url_shortener"
        else:   # punycode
            title = f"Punycode (IDN) domain referenced: {host}"
            severity = Severity.MEDIUM
            confidence = 0.7
            description = (
                f"Aggregated inventory contains `{host}`, an "
                "internationalised domain (one or more labels begin with "
                "`xn--`). IDN domains underpin homoglyph attacks; manually "
                "decode and verify the registered owner."
            )
            fa_key = "punycode"
        return Finding(
            title=title, description=description, severity=severity,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.RAW,
                content=(f"Host: {host}\nFirst seen on: {page}\n"
                         f"Used as: {kinds_str}\n"
                         f"Sample URLs: {entry.sample_urls or []}"),
                location=page,
                source_engine=_ENGINE,
                extra={"host": host, "kinds": sorted(entry.kinds),
                       "sample_urls": list(entry.sample_urls or []),
                       "discovery": "scan_wide_inventory"},
            )],
            confidence=confidence,
            framework=_FA[fa_key],
            scanner_engine=_ENGINE,
            tags=["scan_wide", "inventory"],
            metadata={"host": host, "kinds": sorted(entry.kinds),
                      "first_seen_page": page,
                      "sample_urls": list(entry.sample_urls or []),
                      "discovery": "scan_wide_inventory"},
        )

    # ------------------------------------------------------------------

    async def _run_enrichment(
        self,
        items: list[tuple[str, DomainClassification, set[str]]],
    ) -> list[tuple[str, DomainClassification, set[str],
                    EnrichmentResult | None]]:
        """Run all registered providers on each host in parallel."""
        import asyncio
        assert self._enrichment is not None
        coros = [self._enrichment.enrich_domain(h) for h, _, _ in items]
        results: list[EnrichmentResult | BaseException] = await asyncio.gather(
            *coros, return_exceptions=True,
        )
        out: list[tuple[str, DomainClassification, set[str],
                         EnrichmentResult | None]] = []
        for (host, cls, kinds), enr in zip(items, results):
            out.append((host, cls, kinds,
                         enr if isinstance(enr, EnrichmentResult) else None))
        return out

    def _inventory_finding(self, page_url: str,
                           classifications: list[tuple[str, DomainClassification, set[str],
                                                       EnrichmentResult | None]],
                           by_tier: dict[DomainClass, int]) -> Finding:
        host_lines = []
        for host, cls, kinds, enr in classifications[:30]:
            kinds_str = ",".join(sorted(kinds))
            verdict = (enr.final_classification.value if enr
                       else cls.classification.value)
            ext_note = ""
            if enr and enr.external:
                providers = [r.provider for r in enr.external if r.error is None]
                ext_note = f" providers={','.join(providers)}" if providers else ""
            host_lines.append(
                f"{host:<48s} [{verdict:<22s}] "
                f"score={cls.score:.1f} kinds={kinds_str}{ext_note}"
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
                      severity: Severity, framework_key: str,
                      enrichment: EnrichmentResult | None = None) -> Finding:
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
                    f"Local classification: {cls.classification.value} "
                    f"(score {cls.score:.1f}/10.0, confidence {cls.confidence:.0%})\n"
                    f"Registered: {cls.registerable_domain or '?'}\n"
                    f"TLD: .{cls.tld or '?'}\n"
                    f"Used as: {kinds_str}\n"
                    f"Signals:\n{signal_lines}"
                    + _format_enrichment(enrichment)
                ),
                location=page_url,
                source_engine=_ENGINE,
                extra={
                    "host": host,
                    "classification": cls.classification.value,
                    "score": cls.score,
                    "signals": cls.signals,
                    "kinds": sorted(kinds),
                    **_enrichment_extras(enrichment),
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


def _format_enrichment(enr: EnrichmentResult | None) -> str:
    """Render external-provider verdicts into the evidence content block."""
    if not enr or not enr.external:
        return ""
    lines = ["", "External providers:"]
    for r in enr.external:
        if r.error:
            lines.append(f"  • {r.provider}: error — {r.error}")
            continue
        verdict = "malicious" if r.is_malicious else (
            "suspicious" if r.is_suspicious else "clean"
        )
        rep = (f"{r.reputation_score:.1f}/10.0"
               if r.reputation_score is not None else "n/a")
        cats = f" categories=[{', '.join(r.categories)}]" if r.categories else ""
        lines.append(
            f"  • {r.provider}: {verdict} (rep {rep}, "
            f"confidence {r.confidence:.0%}){cats}"
        )
    lines.append(
        f"Merged verdict: {enr.final_classification.value} "
        f"(score {enr.final_score:.1f}/10.0, "
        f"confidence {enr.final_confidence:.0%})"
    )
    return "\n" + "\n".join(lines)


def _enrichment_extras(enr: EnrichmentResult | None) -> dict[str, object]:
    """Return enrichment metadata for the evidence.extra payload."""
    if not enr or not enr.external:
        return {}
    return {
        "merged_classification": enr.final_classification.value,
        "merged_score": enr.final_score,
        "merged_confidence": enr.final_confidence,
        "external_providers": [
            {
                "provider": r.provider,
                "is_malicious": r.is_malicious,
                "is_suspicious": r.is_suspicious,
                "reputation_score": r.reputation_score,
                "categories": r.categories,
                "error": r.error,
            }
            for r in enr.external
        ],
    }
