# WebHound — scanner/webhound/engines/javascript/source_map_probe.py
# Confirm publicly-accessible source maps with a HEAD probe.
#
# The passive check in js_analyzer.py detects `//# sourceMappingURL=` comments
# in inline scripts. That tells you the BUILD intended to ship a source map —
# not whether the map is actually publicly downloadable. This engine resolves
# each map URL relative to the page and HEADs it. If it returns 2xx, we
# escalate the finding from LOW to MEDIUM with high confidence.

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

if TYPE_CHECKING:
    from webhound.core.extractor import PageArtifacts
    from webhound.core.http_client import SafeHttpClient

_ENGINE = "source_map_probe"

# Match the sourceMappingURL directive — both legacy `//@` and modern `//#`.
# Captures the URL as group 1.
_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.I)


class SourceMapProbeEngine:
    """Confirms publicly-accessible source maps via HEAD requests."""

    NAME = _ENGINE

    def __init__(self, client: "SafeHttpClient") -> None:
        self._client = client

    async def analyze(self, artifacts: "PageArtifacts") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for content in artifacts.inline_scripts:
            for m in _SOURCE_MAP_RE.finditer(content):
                raw = m.group(1).strip()
                # Source maps are most often relative — resolve against the page URL.
                map_url = urljoin(artifacts.url, raw)
                if map_url in seen:
                    continue
                seen.add(map_url)
                finding = await self._probe_one(map_url, artifacts.url)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _probe_one(self, map_url: str, page_url: str) -> Finding | None:
        try:
            response = await self._client.head(map_url)
        except Exception:
            return None
        if response.failed:
            return None
        if not (200 <= response.status_code < 300):
            return None
        ev = Evidence(
            evidence_type=EvidenceType.JAVASCRIPT,
            content=(
                f"HEAD {map_url} -> HTTP {response.status_code}\n"
                "Source map is publicly downloadable."
            ),
            location=map_url,
            source_engine=_ENGINE,
            extra={
                "map_url": map_url,
                "http_status": response.status_code,
            },
        )
        return Finding(
            title="Source map is publicly accessible — original code is leaking",
            description=(
                f"Your site references `{map_url}` from a `sourceMappingURL` "
                "comment, and the map file is actually downloadable. Anyone can "
                "fetch it and reconstruct your original (un-minified) source — "
                "including comments, internal API URLs, environment hints, "
                "and any secret accidentally checked in to your source tree."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.JAVASCRIPT,
            evidence=[ev],
            confidence=0.97,  # HEAD-confirmed
            remediation=(
                "Pick one:\n"
                "  1. Stop generating maps for production builds. Most bundlers "
                "support `sourcemap: false` or `sourcemap: 'hidden'`.\n"
                "  2. Generate the maps but don't deploy them — keep them in your "
                "error-tracker (Sentry / Datadog / etc.) where only your team "
                "can see them.\n"
                "  3. Deny `*.map` requests at your CDN or web server:\n"
                "     nginx:  location ~ \\.map$ { deny all; }\n"
                "     Cloudflare: Page Rules -> URL contains `.map` -> Block"
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-540", "CWE-200"],
                nist_controls=["SC-30", "AC-3"],
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_score=5.3,
                pci_dss=["6.5.5"],
                iso_27001=["A.5.34", "A.8.32"],
                soc2=["CC6.1"],
                exploitability=Exploitability.KNOWN_EXPLOITED,
            ),
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "map_url": map_url},
        )
