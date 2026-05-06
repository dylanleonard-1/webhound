# WebHound — scanner/webhound/engines/recon/technology.py
# Passive technology fingerprinting from HTTP headers, meta tags, and script URLs.
#
# Safe-mode: reads pre-extracted PageArtifacts only.
# No active probing, no version scanning, no exploitation.

from __future__ import annotations

import re

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "technology"

# Regex to detect version numbers in header values (e.g. "Apache/2.4.48", "PHP/7.4").
_VERSION_RE = re.compile(r"/(\d+[\d.]+)")

# Script URL patterns for common frameworks/libraries.
_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jQuery",      re.compile(r"jquery[-./]", re.I)),
    ("React",       re.compile(r"/react(?:\.min)?\.js|react-dom", re.I)),
    ("Vue.js",      re.compile(r"/vue(?:\.min|\.global)?\.js|/vue@", re.I)),
    ("Angular",     re.compile(r"/angular(?:\.min)?\.js|/angular@", re.I)),
    ("Bootstrap",   re.compile(r"bootstrap(?:\.min|\.bundle)?\.js", re.I)),
    ("Next.js",     re.compile(r"/_next/static/", re.I)),
    ("Nuxt.js",     re.compile(r"/_nuxt/", re.I)),
    ("Ember.js",    re.compile(r"/ember(?:\.min)?\.js", re.I)),
    ("Svelte",      re.compile(r"/svelte(?:\.min)?\.js", re.I)),
]


class TechnologyEngine:
    """Passive technology fingerprinting from page artifacts.

    Detects CMS platforms, CDN/WAF presence, frontend frameworks, and server
    technology from HTTP headers, meta tags, and script URLs.

    All findings are :attr:`Severity.INFO` except explicit version disclosures
    which are :attr:`Severity.LOW` (information disclosure risk).

    Call ``analyze(artifacts)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_cms(artifacts))
        findings.extend(self._detect_cdn_waf(artifacts))
        findings.extend(self._detect_frameworks(artifacts))
        findings.extend(self._detect_server_disclosure(artifacts))
        return findings

    # ------------------------------------------------------------------
    # CMS / platform detection
    # ------------------------------------------------------------------

    def _detect_cms(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        h = artifacts.response_headers
        meta = artifacts.meta_tags

        # WordPress
        if (
            "wordpress" in meta.get("generator", "").lower()
            or "wordpress" in h.get("x-powered-by", "").lower()
            or "wordpress" in h.get("x-redirect-by", "").lower()
            or any("/wp-content/" in u or "/wp-includes/" in u
                   for u in artifacts.external_script_urls)
            or any("/wp-admin" in u or "/wp-login.php" in u
                   for u in artifacts.all_links)
        ):
            findings.append(_info_finding(
                "WordPress detected",
                "WordPress CMS was identified via meta generator tag, headers, or "
                "characteristic URL paths (/wp-content/, /wp-admin/). "
                "Ensure WordPress core, themes, and plugins are kept up to date.",
                _header_or_meta_ev("WordPress", artifacts),
                artifacts.url,
            ))

        # Shopify
        if (
            "shopify" in meta.get("generator", "").lower()
            or "x-shopify-stage" in h
            or "x-shopify-request-id" in h
            or any("cdn.shopify.com" in u for u in artifacts.external_script_urls)
        ):
            findings.append(_info_finding(
                "Shopify detected",
                "The Shopify e-commerce platform was identified. "
                "Ensure app permissions are minimal and third-party Shopify apps "
                "are regularly audited.",
                _header_or_meta_ev("Shopify", artifacts),
                artifacts.url,
            ))

        # Wix
        if (
            "wix" in meta.get("generator", "").lower()
            or any("static.wixstatic.com" in u for u in artifacts.external_script_urls)
        ):
            findings.append(_info_finding(
                "Wix detected",
                "The Wix website builder platform was identified. "
                "Ensure Wix apps are reviewed and unnecessary integrations removed.",
                _header_or_meta_ev("Wix", artifacts),
                artifacts.url,
            ))

        # Drupal
        if (
            "drupal" in meta.get("generator", "").lower()
            or "x-drupal-cache" in h
            or "x-generator" in h and "drupal" in h.get("x-generator", "").lower()
        ):
            findings.append(_info_finding(
                "Drupal detected",
                "The Drupal CMS was identified. "
                "Ensure Drupal core and contributed modules are kept up to date.",
                _header_or_meta_ev("Drupal", artifacts),
                artifacts.url,
            ))

        # Joomla
        if "joomla" in meta.get("generator", "").lower():
            findings.append(_info_finding(
                "Joomla detected",
                "The Joomla CMS was identified via the generator meta tag. "
                "Ensure Joomla core and extensions are kept up to date.",
                Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<meta name=\"generator\" content=\"{meta.get('generator')}\">",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        return findings

    # ------------------------------------------------------------------
    # CDN / WAF detection
    # ------------------------------------------------------------------

    def _detect_cdn_waf(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        h = artifacts.response_headers
        srv = h.get("server", "").lower()

        # Cloudflare
        if "cf-ray" in h or "cloudflare" in srv:
            findings.append(_info_finding(
                "Cloudflare CDN/WAF detected",
                "Cloudflare is in the request path (cf-ray header or server: cloudflare). "
                "Cloudflare provides DDoS mitigation and WAF capabilities. "
                "Ensure WAF rules are properly configured.",
                Evidence(
                    evidence_type=EvidenceType.HEADER,
                    content=f"cf-ray: {h.get('cf-ray', '<present>')}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        # AWS CloudFront
        if h.get("x-amz-cf-id") or "cloudfront" in h.get("via", "").lower():
            findings.append(_info_finding(
                "AWS CloudFront CDN detected",
                "AWS CloudFront is serving this content (x-amz-cf-id or via: cloudfront). "
                "Review CloudFront distribution security settings and origin policies.",
                Evidence(
                    evidence_type=EvidenceType.HEADER,
                    content=f"x-amz-cf-id: {h.get('x-amz-cf-id', '<via header>')}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        # Fastly
        if h.get("x-fastly-request-id") or h.get("x-served-by", "").startswith("cache-"):
            findings.append(_info_finding(
                "Fastly CDN detected",
                "Fastly CDN is serving this content. "
                "Review Fastly VCL configuration and origin security settings.",
                Evidence(
                    evidence_type=EvidenceType.HEADER,
                    content=f"x-fastly-request-id: {h.get('x-fastly-request-id', '<present>')}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        # Sucuri WAF
        if h.get("x-sucuri-id") or "sucuri" in srv:
            findings.append(_info_finding(
                "Sucuri WAF detected",
                "The Sucuri Web Application Firewall is in the request path. "
                "Ensure WAF rules are up to date and bypass techniques are mitigated.",
                Evidence(
                    evidence_type=EvidenceType.HEADER,
                    content=f"x-sucuri-id: {h.get('x-sucuri-id', '<server header>')}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        # Imperva / Incapsula
        if h.get("x-iinfo"):
            findings.append(_info_finding(
                "Imperva/Incapsula WAF detected",
                "The Imperva/Incapsula WAF is in the request path (x-iinfo header). "
                "Ensure WAF rules are actively maintained.",
                Evidence(
                    evidence_type=EvidenceType.HEADER,
                    content=f"x-iinfo: {h['x-iinfo']}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                ),
                artifacts.url,
            ))

        return findings

    # ------------------------------------------------------------------
    # Frontend framework detection
    # ------------------------------------------------------------------

    def _detect_frameworks(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for url in artifacts.external_script_urls + artifacts.all_links:
            for name, pattern in _FRAMEWORK_PATTERNS:
                if name in seen:
                    continue
                if pattern.search(url):
                    seen.add(name)
                    ev = Evidence(
                        evidence_type=EvidenceType.JAVASCRIPT,
                        content=f"{name} detected in resource URL: {url}",
                        location=artifacts.url,
                        source_engine=_ENGINE,
                        extra={"framework": name, "detected_url": url},
                    )
                    findings.append(_info_finding(
                        f"{name} detected",
                        f"The {name} JavaScript framework/library was identified from "
                        f"resource URL patterns. Keep {name} updated to the latest "
                        "version to receive security patches.",
                        ev,
                        artifacts.url,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Server / stack version disclosure
    # ------------------------------------------------------------------

    def _detect_server_disclosure(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        h = artifacts.response_headers

        for header_name in ("server", "x-powered-by", "x-aspnet-version",
                             "x-aspnetmvc-version"):
            value = h.get(header_name, "")
            if not value:
                continue

            if _VERSION_RE.search(value):
                ev = Evidence.http_header(header_name, value, artifacts.url, _ENGINE)
                findings.append(Finding(
                    title=f"Server version disclosed in {header_name} header",
                    description=(
                        f"The response header '{header_name}: {value}' reveals the "
                        "server software version. Attackers use this to target "
                        "known CVEs for the specific version."
                    ),
                    severity=Severity.LOW,
                    category=FindingCategory.TECHNOLOGY,
                    evidence=[ev],
                    confidence=1.0,
                    remediation=(
                        f"Suppress or obscure the '{header_name}' header. "
                        "In Apache: ServerTokens Prod / ServerSignature Off. "
                        "In nginx: server_tokens off. In IIS: use URL Rewrite "
                        "to remove the header."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-200"],
                        nist_controls=["SI-12"],
                    ),
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url},
                ))
            elif value.strip():
                ev = Evidence.http_header(header_name, value, artifacts.url, _ENGINE)
                findings.append(_info_finding(
                    f"Technology disclosed via {header_name} header",
                    f"The response header '{header_name}: {value}' discloses the "
                    "server/platform technology. This aids attacker reconnaissance.",
                    ev,
                    artifacts.url,
                ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _header_or_meta_ev(technology: str, artifacts: PageArtifacts) -> Evidence:
    h = artifacts.response_headers
    meta = artifacts.meta_tags
    if "generator" in meta and technology.lower() in meta["generator"].lower():
        return Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=f"<meta name=\"generator\" content=\"{meta['generator']}\">",
            location=artifacts.url,
            source_engine=_ENGINE,
        )
    for key, val in h.items():
        if technology.lower() in val.lower():
            return Evidence.http_header(key, val, artifacts.url, _ENGINE)
    # Fallback: indicate detection via script URL patterns
    return Evidence(
        evidence_type=EvidenceType.JAVASCRIPT,
        content=f"{technology} detected via script URL patterns",
        location=artifacts.url,
        source_engine=_ENGINE,
    )


def _info_finding(
    title: str,
    description: str,
    evidence: Evidence,
    url: str,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=Severity.INFO,
        category=FindingCategory.TECHNOLOGY,
        evidence=[evidence],
        confidence=0.85,
        remediation=None,
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"],
            cwe_ids=["CWE-200"],
        ),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
