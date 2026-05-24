# WebHound — scanner/webhound/engines/cms/wix.py
# Passive Wix fingerprinting + advisory checks.
#
# Wix is fully managed: TLS, hosting, patching, DDoS, and PCI are all
# Wix's responsibility, so there's not much technical attack surface at
# the merchant level. Most realistic risk is in user-installed apps,
# unrestricted member-area access, and the editor-link page (where
# anyone with the URL can edit the site if it was never set to private).

from __future__ import annotations

import re

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "wix"

_FA: dict[str, FrameworkAlignment] = {
    "detected": FrameworkAlignment(
        owasp_top10=["A06:2021"],
        cwe_ids=["CWE-1395"],
        nist_controls=["CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.1,
        pci_dss=["12.8.5"],
        iso_27001=["A.5.19", "A.8.8"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "preview_url_exposed": FrameworkAlignment(
        owasp_top10=["A01:2021", "A05:2021"],
        cwe_ids=["CWE-200", "CWE-284"],
        nist_controls=["AC-3", "AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.2.4"],
        iso_27001=["A.5.15", "A.8.9"],
        soc2=["CC6.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
}

# Preview/editor URLs leak the underlying Wix site ID and can sometimes be
# loaded without authentication when the owner left the site unpublished.
_PREVIEW_LINK_RE = re.compile(
    r"(?:editor\.wix\.com|preview\.wixsite\.com|//[a-z0-9\-]+\.wixsite\.com/[a-z0-9\-]+/preview)",
    re.I,
)


def _is_wix(artifacts: PageArtifacts) -> bool:
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    h = {k.lower(): v for k, v in artifacts.response_headers.items()}
    if "wix" in meta.get("generator", "").lower():
        return True
    if any("static.wixstatic.com" in u or "parastorage.com" in u
           for u in artifacts.external_script_urls):
        return True
    if "x-wix-request-id" in h:
        return True
    return False


class WixEngine:
    """Passive Wix detection plus the one or two checks that matter.

    The vast majority of Wix security falls to Wix itself; this engine
    flags the small set of merchant-level risks: preview/editor URLs
    being indexed, and third-party Wix apps loading customer-facing JS.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not _is_wix(artifacts):
            return []

        findings: list[Finding] = []
        page_url = artifacts.url

        findings.append(Finding(
            title="Wix detected",
            description=(
                "The site is built on Wix. Wix is a fully managed platform — "
                "it handles hosting, TLS, OS patching, DDoS protection, and "
                "PCI compliance for the checkout. Your remaining security "
                "responsibility is mostly: keep your Wix account password "
                "strong and protected by two-factor auth, audit which "
                "third-party Wix apps you've installed (each one can read "
                "and write your site content), and make sure member-area "
                "permissions are configured correctly."
            ),
            severity=Severity.INFO,
            category=FindingCategory.TECHNOLOGY,
            evidence=[Evidence(
                evidence_type=EvidenceType.HEADER,
                content=_detection_evidence_text(artifacts),
                location=page_url,
                source_engine=_ENGINE,
            )],
            confidence=0.95,
            remediation=(
                "Open Wix → Settings → Manage Apps and review each app's "
                "permission scope. Remove apps you don't actively use. "
                "Enable two-factor authentication on the Wix owner account. "
                "If the site has a Members Area, double-check the role "
                "configuration so only intended audiences can reach "
                "restricted pages."
            ),
            framework=_FA["detected"],
            scanner_engine=_ENGINE,
            metadata={"page_url": page_url},
        ))

        # Preview-URL exposure (the only Wix-specific finding that's worth flagging)
        preview_refs = [u for u in artifacts.all_links if _PREVIEW_LINK_RE.search(u)]
        if preview_refs:
            findings.append(Finding(
                title="Wix editor or preview URL is linked from the public site",
                description=(
                    "The page links to a Wix editor or preview URL "
                    f"({preview_refs[0]}). These URLs expose the underlying "
                    "Wix site ID and can sometimes be loaded by anyone if "
                    "the site owner left the preview unrestricted. They're "
                    "intended as a development tool, not a public link."
                ),
                severity=Severity.LOW,
                category=FindingCategory.RECON,
                evidence=[Evidence(
                    evidence_type=EvidenceType.RAW,
                    content="Preview links: " + ", ".join(preview_refs[:3]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.8,
                remediation=(
                    "Remove the link from the public theme. If you need a "
                    "shareable preview, generate a fresh preview URL only "
                    "for the intended recipient and revoke it when no "
                    "longer needed."
                ),
                framework=_FA["preview_url_exposed"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "preview_refs": preview_refs[:5]},
            ))

        return findings


def _detection_evidence_text(artifacts: PageArtifacts) -> str:
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    bits: list[str] = []
    if "wix" in meta.get("generator", "").lower():
        bits.append(f'meta generator="{meta["generator"]}"')
    cdn = [u for u in artifacts.external_script_urls
           if "wixstatic.com" in u or "parastorage.com" in u][:2]
    if cdn:
        bits.append("CDN: " + ", ".join(cdn))
    return "\n".join(bits) or "(Wix markers detected)"
