# WebHound — scanner/webhound/engines/recon/robots_sitemap.py
# Passive analysis of robots.txt and sitemap.xml for recon exposure.
#
# Safe-mode: GET only. No active probing of disallowed paths.
# Detects sensitive path disclosure in public recon files.

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from webhound.core.http_client import SafeHttpClient
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity
from webhound.models.target import Target

_ENGINE = "robots_sitemap"

_FA: dict[str, FrameworkAlignment] = {
    "robots_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", cvss_score=0.0,
        iso_27001=["A.5.34"],
        exploitability=Exploitability.UNKNOWN,
    ),
    "robots_malformed": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "robots_disclosure": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200", "CWE-284"], nist_controls=["CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.5.5"], iso_27001=["A.5.34", "A.8.32"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "sitemap_disclosure": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.5.5"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
}

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"

# Paths in robots.txt Disallow/Allow that reveal sensitive areas.
_SENSITIVE_DISALLOW_RE = re.compile(
    r"^/(?:admin(?:istrat(?:or|ion))?|wp-admin|wp-login|backend|staff|"
    r"manage(?:ment)?|dashboard|"
    r"debug|staging|dev(?:elopment)?|beta|qa|uat|test(?:ing)?|"
    r"internal|private|api/internal|api/admin|"
    r"backup(?:s)?|bak|db|database(?:s)?|sql|dumps?|"
    r"config(?:uration)?|settings?|"
    r"\.env|\.git|phpinfo|phpmyadmin|pma|adminer|"
    r"cron|crons?|jobs?/internal|"
    r"install|setup|update|upgrade)(?:/.*)?$",
    re.I,
)

# Sensitive path patterns for sitemap URL analysis.
_SENSITIVE_SITEMAP_RE = re.compile(
    r"/(?:admin(?:istrat(?:or|ion))?|wp-admin|wp-login|"
    r"debug|staging|dev(?:elopment)?|beta|internal|private|"
    r"backup|database|install|setup|phpmyadmin|phpinfo)(?:/|$)",
    re.I,
)


def _parse_robots(content: str) -> tuple[list[str], list[str], list[str]]:
    """Extract (disallow_paths, allow_paths, sitemap_urls) from robots.txt content."""
    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("disallow:"):
            path = line[9:].split("#")[0].strip()
            if path:
                disallow.append(path)
        elif lower.startswith("allow:"):
            path = line[6:].split("#")[0].strip()
            if path:
                allow.append(path)
        elif lower.startswith("sitemap:"):
            url = line[8:].split("#")[0].strip()
            if url:
                sitemaps.append(url)

    return disallow, allow, sitemaps


def _looks_like_robots(content: str) -> bool:
    """Heuristic check that content resembles a robots.txt file."""
    if not content.strip():
        return False
    lower = content.lower()
    return any(d in lower for d in ("user-agent:", "disallow:", "allow:", "sitemap:"))


def _parse_sitemap_urls(xml_body: str) -> list[str]:
    """Extract <loc> URLs from sitemap XML, handling namespace variations."""
    urls: list[str] = []
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return urls

    # Namespaced elements (standard)
    for elem in root.iter(f"{{{_SITEMAP_NS}}}loc"):
        if elem.text:
            urls.append(elem.text.strip())

    # Fallback: no namespace
    if not urls:
        for elem in root.iter("loc"):
            if elem.text:
                urls.append(elem.text.strip())

    return urls


def _url_path(url: str) -> str:
    try:
        return urlparse(url).path.lower()
    except Exception:
        return url.lower()


def _on_target_host(url: str, target: Target) -> bool:
    """True if *url* is on the same hostname as the target."""
    try:
        return (urlparse(url).hostname or "").lower() == target.hostname.lower()
    except Exception:
        return False


def _info_finding(title: str, description: str, evidence_content: str, url: str, kind: str = "robots_missing") -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=Severity.INFO,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            content=evidence_content,
            location=url,
            source_engine=_ENGINE,
        )],
        confidence=0.9,
        remediation=None,
        framework=_FA[kind],
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )


class RobotsAndSitemapEngine:
    """Passive analysis of robots.txt and sitemap.xml for recon exposure.

    Fetches and analyzes:
    - ``/robots.txt`` — disallow/allow paths, sitemap references
    - ``/sitemap.xml`` and any Sitemap: URLs found in robots.txt

    Detects:
    - Sensitive paths inadvertently disclosed in Disallow directives
    - Sensitive or internal URLs listed in sitemaps
    - Missing robots.txt (INFO only — not a vulnerability)
    - Malformed robots.txt content (LOW/INFO)

    No active probing of disallowed paths is performed.

    Call ``await analyze(target, client)`` to receive a list of findings.
    """

    NAME = _ENGINE

    async def analyze(
        self,
        target: Target,
        client: SafeHttpClient,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # -- robots.txt --
        robots_url = f"{target.base_url}/robots.txt"
        robots_resp = await client.get(robots_url)

        if robots_resp.failed or robots_resp.status_code == 404:
            findings.append(_info_finding(
                "No robots.txt file",
                "There's no robots.txt at the expected location. That isn't a "
                "security issue — robots.txt is a crawl-control hint, not a "
                "lock — but its absence means you have no signal to search "
                "engines about which paths to ignore. Informational only.",
                f"HTTP {robots_resp.status_code if not robots_resp.failed else 'error'} {robots_url}",
                robots_url,
                kind="robots_missing",
            ))
            sitemap_urls: list[str] = []
        elif not robots_resp.is_success:
            return findings
        else:
            content = robots_resp.body
            if not _looks_like_robots(content):
                findings.append(Finding(
                    title="Your robots.txt doesn't look like a valid robots.txt",
                    description=(
                        "There's a file at /robots.txt but it doesn't contain the "
                        "directives well-behaved crawlers expect (User-agent, "
                        "Disallow, Allow, Sitemap). Search engines may ignore it "
                        "entirely — meaning any crawl-control intentions you have "
                        "aren't actually being applied."
                    ),
                    severity=Severity.LOW,
                    category=FindingCategory.RECON,
                    evidence=[Evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        content=content[:300],
                        location=robots_url,
                        source_engine=_ENGINE,
                        status_code=robots_resp.status_code,
                    )],
                    confidence=0.8,
                    remediation=(
                        "Replace with a valid robots.txt. Minimal example:\n"
                        "  User-agent: *\n"
                        "  Allow: /\n"
                        "  Sitemap: https://yourdomain.com/sitemap.xml"
                    ),
                    framework=_FA["robots_malformed"],
                    scanner_engine=_ENGINE,
                    metadata={"url": robots_url},
                ))
                sitemap_urls = []
            else:
                disallow, _, sitemap_urls = _parse_robots(content)
                findings.extend(self._check_disallow_paths(disallow, robots_url))

        # -- sitemaps --
        # Only fetch sitemaps on the same hostname to prevent SSRF via
        # a crafted robots.txt that references external Sitemap: URLs.
        safe_sitemaps = [
            u for u in sitemap_urls
            if _on_target_host(u, target)
        ]
        sitemap_candidates: list[str] = list(dict.fromkeys(
            safe_sitemaps + [f"{target.base_url}/sitemap.xml"]
        ))

        # Also try sitemap_index.xml and sitemap-news.xml — both are common
        # variants that often live alongside (or instead of) sitemap.xml.
        sitemap_candidates.extend([
            f"{target.base_url}/sitemap_index.xml",
            f"{target.base_url}/sitemap-news.xml",
        ])

        for sitemap_url in sitemap_candidates[:5]:
            sitemap_resp = await client.get(sitemap_url)
            if sitemap_resp.is_success and sitemap_resp.body:
                urls = _parse_sitemap_urls(sitemap_resp.body)
                findings.extend(self._check_sitemap_urls(urls, sitemap_url))

        # ── .well-known/security.txt (RFC 9116) ──
        # Presence = informational good signal. Absence = informational only.
        security_txt_url = f"{target.base_url}/.well-known/security.txt"
        sec_resp = await client.get(security_txt_url)
        if sec_resp.is_success and sec_resp.body and "contact" in sec_resp.body.lower():
            findings.append(_info_finding(
                "security.txt published (RFC 9116)",
                "Your site publishes a security.txt file at the standard location. "
                "Researchers and bug-bounty hunters use this to find your security "
                "contact and reporting policy — having it is best practice and a "
                "small but real signal of security maturity. No action needed.",
                f"HTTP {sec_resp.status_code} {security_txt_url}\n{sec_resp.body[:200]}",
                security_txt_url, kind="robots_missing",
            ))
        elif sec_resp.failed or sec_resp.status_code == 404:
            findings.append(_info_finding(
                "No security.txt — researchers don't know how to contact you",
                "There's no /.well-known/security.txt file. RFC 9116 recommends "
                "this small text file so independent researchers and bug-bounty "
                "hunters know where to report vulnerabilities they find on your "
                "site. Costs nothing, signals you take responsible disclosure "
                "seriously.",
                f"HTTP {sec_resp.status_code if not sec_resp.failed else 'error'} {security_txt_url}",
                security_txt_url, kind="robots_missing",
            ))

        return findings

    def _check_disallow_paths(
        self,
        paths: list[str],
        robots_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for path in paths:
            if not _SENSITIVE_DISALLOW_RE.match(path):
                continue
            key = path.lower().rstrip("/")
            if key in seen:
                continue
            seen.add(key)

            findings.append(Finding(
                title="Your robots.txt advertises a sensitive admin / dev path",
                description=(
                    f"Your robots.txt lists `Disallow: {path}` — which means anyone "
                    "reading the file (and it's public to anyone with a browser) now "
                    "knows that path exists. robots.txt is a polite request to crawlers, "
                    "not access control. Attackers read it FIRST when reconning a site."
                ),
                severity=Severity.LOW,
                category=FindingCategory.RECON,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTTP_RESPONSE,
                    content=f"Disallow: {path}",
                    location=robots_url,
                    source_engine=_ENGINE,
                    status_code=200,
                    extra={"disallow_path": path},
                )],
                confidence=0.9,
                remediation=(
                    "Stop using robots.txt to 'hide' admin or dev paths — it does the "
                    "opposite. Protect those paths with authentication + authorization "
                    "and remove them from robots.txt. If you do need to keep them out of "
                    "search results, use a `noindex` meta tag or X-Robots-Tag header on "
                    "the actual pages instead — those aren't broadcast in a public file."
                ),
                framework=_FA["robots_disclosure"],
                scanner_engine=_ENGINE,
                metadata={"url": robots_url, "path": path},
            ))

        return findings

    def _check_sitemap_urls(
        self,
        urls: list[str],
        sitemap_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for url in urls:
            if not _SENSITIVE_SITEMAP_RE.search(url):
                continue
            path = _url_path(url)
            if path in seen:
                continue
            seen.add(path)

            findings.append(Finding(
                title="Your sitemap lists an admin / dev / internal URL",
                description=(
                    f"Your sitemap at `{sitemap_url}` contains `{url[:120]}`, which "
                    "looks like an admin panel, staging environment, or other internal "
                    "page. Sitemaps are public and submitted to search engines — "
                    "anything in them is treated as 'please index this'. Internal pages "
                    "shouldn't be there."
                ),
                severity=Severity.LOW,
                category=FindingCategory.RECON,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTTP_RESPONSE,
                    content=f"<loc>{url[:200]}</loc>",
                    location=sitemap_url,
                    source_engine=_ENGINE,
                    status_code=200,
                    extra={"sensitive_url": url},
                )],
                confidence=0.75,
                remediation=(
                    "Remove internal / admin / staging URLs from sitemap generation. "
                    "Sitemaps are for production content you actively want indexed."
                ),
                framework=_FA["sitemap_disclosure"],
                scanner_engine=_ENGINE,
                metadata={"url": sitemap_url, "sensitive_url": url},
            ))

        return findings
