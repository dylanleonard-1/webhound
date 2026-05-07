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
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity
from webhound.models.target import Target

_ENGINE = "robots_sitemap"

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


def _info_finding(title: str, description: str, evidence_content: str, url: str) -> Finding:
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
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"],
            cwe_ids=["CWE-200"],
        ),
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
                "robots.txt not found",
                "No robots.txt file was found at the expected location. "
                "A robots.txt is not a security requirement, but its absence means "
                "no crawl directives are in place. This is informational only.",
                f"HTTP {robots_resp.status_code if not robots_resp.failed else 'error'} {robots_url}",
                robots_url,
            ))
            sitemap_urls: list[str] = []
        elif not robots_resp.is_success:
            return findings
        else:
            content = robots_resp.body
            if not _looks_like_robots(content):
                findings.append(Finding(
                    title="Malformed or unexpected robots.txt content",
                    description=(
                        "The robots.txt file exists but does not appear to contain valid "
                        "robots.txt directives (User-agent:, Disallow:, Allow:, Sitemap:). "
                        "This may indicate a misconfiguration or a placeholder file."
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
                        "Review and fix the robots.txt file to contain valid directives. "
                        "An invalid robots.txt may be ignored by well-behaved crawlers."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-200"],
                    ),
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

        for sitemap_url in sitemap_candidates[:3]:
            sitemap_resp = await client.get(sitemap_url)
            if sitemap_resp.is_success and sitemap_resp.body:
                urls = _parse_sitemap_urls(sitemap_resp.body)
                findings.extend(self._check_sitemap_urls(urls, sitemap_url))

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
                title="Sensitive path disclosed in robots.txt Disallow",
                description=(
                    f"The robots.txt Disallow directive reveals the path '{path}', "
                    "which appears to be a sensitive or restricted area. "
                    "robots.txt is a public document readable by anyone, so Disallow "
                    "directives inadvertently advertise the existence of these paths "
                    "to attackers and search engine crawlers alike."
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
                    "Do not rely on robots.txt to protect sensitive paths — it provides "
                    "no access control and actively reveals the paths it tries to hide. "
                    "Protect sensitive areas with authentication and authorization instead. "
                    "Consider removing sensitive paths from Disallow directives."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-200", "CWE-284"],
                    nist_controls=["CM-7"],
                ),
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
                title="Sensitive path exposed in sitemap",
                description=(
                    f"The sitemap at '{sitemap_url}' lists the URL '{url[:120]}', "
                    "which contains a path segment associated with admin panels, "
                    "development environments, or other sensitive areas. "
                    "Sitemaps are public documents intended for search engine indexing "
                    "and should not include internal or sensitive URLs."
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
                    "Remove sensitive, internal, or development URLs from the sitemap. "
                    "Sitemaps should only contain publicly accessible, production content "
                    "that you intend to be indexed."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-200"],
                    nist_controls=["CM-7"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": sitemap_url, "sensitive_url": url},
            ))

        return findings
