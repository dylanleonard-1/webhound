# WebHound — scanner/webhound/engines/cms/wordpress.py
# Passive WordPress fingerprinting + security checks.
#
# Safe-mode: reads pre-extracted PageArtifacts only. No probing, no
# unauthenticated /wp-login.php hits, no /wp-json/ user enumeration.
# Every signal here comes from artifacts the crawler already fetched.

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "wordpress"

# Newest stable major branch as of the engine cut. Anything ≥ this is treated
# as "current"; older versions cross severity thresholds based on the major.
_CURRENT_BRANCH = (6, 4)

# Versions are reasoned about by major.minor. Patch level rarely
# disambiguates a vulnerability class in passive analysis.
_VERSION_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?\b")

# Plugin/theme path patterns inside script/style/image URLs.
_PLUGIN_PATH_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9][a-z0-9._\-]+)/",
    re.I,
)
_THEME_PATH_RE = re.compile(
    r"/wp-content/themes/([a-z0-9][a-z0-9._\-]+)/",
    re.I,
)

_VER_QS_KEY = "ver"

_FA: dict[str, FrameworkAlignment] = {
    "detected": FrameworkAlignment(
        owasp_top10=["A06:2021"],
        cwe_ids=["CWE-1395"],
        nist_controls=["CM-8", "SI-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.8"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "version_disclosure": FrameworkAlignment(
        owasp_top10=["A05:2021", "A06:2021"],
        cwe_ids=["CWE-200", "CWE-1395"],
        nist_controls=["CM-7", "SI-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.8", "A.8.9"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "outdated_high": FrameworkAlignment(
        owasp_top10=["A06:2021"],
        cwe_ids=["CWE-1104", "CWE-1395"],
        nist_controls=["SI-2", "CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        pci_dss=["6.3.3", "11.3.1"],
        iso_27001=["A.8.8"],
        soc2=["CC7.1"],
        hipaa=["164.308(a)(8)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "outdated_medium": FrameworkAlignment(
        owasp_top10=["A06:2021"],
        cwe_ids=["CWE-1104", "CWE-1395"],
        nist_controls=["SI-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=6.5,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.8"],
        soc2=["CC7.1"],
        hipaa=["164.308(a)(8)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "xmlrpc": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-1188", "CWE-307"],
        nist_controls=["AC-7", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cvss_score=6.3,
        pci_dss=["6.4.1", "8.3.4"],
        iso_27001=["A.8.5", "A.8.9"],
        soc2=["CC6.1", "CC7.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "wp_json_exposed": FrameworkAlignment(
        owasp_top10=["A01:2021", "A05:2021"],
        cwe_ids=["CWE-200", "CWE-284"],
        nist_controls=["AC-3", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        pci_dss=["6.2.4", "7.2.1"],
        iso_27001=["A.5.15", "A.8.9"],
        soc2=["CC6.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "readme_exposed": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-200"],
        nist_controls=["CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.9"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "login_exposed": FrameworkAlignment(
        owasp_top10=["A01:2021", "A07:2021"],
        cwe_ids=["CWE-307"],
        nist_controls=["AC-7", "IA-5"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["8.3.4", "8.3.6"],
        iso_27001=["A.5.15", "A.5.17"],
        soc2=["CC6.1"],
        hipaa=["164.308(a)(5)(ii)(D)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "plugin_enum": FrameworkAlignment(
        owasp_top10=["A05:2021", "A06:2021"],
        cwe_ids=["CWE-200", "CWE-1395"],
        nist_controls=["CM-7", "SI-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=4.3,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.8"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
}


def _is_wordpress(artifacts: PageArtifacts) -> bool:
    h = {k.lower(): v for k, v in artifacts.response_headers.items()}
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    if "wordpress" in meta.get("generator", "").lower():
        return True
    if "wordpress" in h.get("x-powered-by", "").lower():
        return True
    if "wordpress" in h.get("x-redirect-by", "").lower():
        return True
    if any("/wp-content/" in u or "/wp-includes/" in u
           for u in artifacts.external_script_urls):
        return True
    if any("/wp-content/" in u or "/wp-includes/" in u
           for u in artifacts.external_stylesheet_urls):
        return True
    if any("/wp-admin" in u or "/wp-login.php" in u or "/xmlrpc.php" in u
           for u in artifacts.all_links):
        return True
    return False


def _extract_version_from_meta(meta: dict[str, str]) -> str | None:
    gen = meta.get("generator") or ""
    if "wordpress" not in gen.lower():
        return None
    m = _VERSION_RE.search(gen)
    if not m:
        return None
    return ".".join(g for g in m.groups() if g is not None)


def _extract_version_from_querystrings(artifacts: PageArtifacts) -> str | None:
    for url in (artifacts.external_script_urls + artifacts.external_stylesheet_urls):
        if "/wp-includes/" not in url:
            continue
        qs = parse_qs(urlparse(url).query)
        ver_values = qs.get(_VER_QS_KEY)
        if not ver_values:
            continue
        m = _VERSION_RE.search(ver_values[0])
        if m:
            return ".".join(g for g in m.groups() if g is not None)
    return None


def _parse_major_minor(version: str) -> tuple[int, int] | None:
    m = _VERSION_RE.search(version)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _is_outdated(version: str) -> tuple[bool, str]:
    parsed = _parse_major_minor(version)
    if not parsed:
        return False, "none"
    major, minor = parsed
    current_major, current_minor = _CURRENT_BRANCH
    # Two or more majors behind → HIGH (e.g. 4.x when current is 6.x)
    if major <= current_major - 2:
        return True, "high"
    # Exactly one major behind → MEDIUM (5.x when current is 6.x)
    if major == current_major - 1:
        return True, "medium"
    # Same major but two or more minor versions behind → MEDIUM
    if major == current_major and minor < current_minor - 1:
        return True, "medium"
    return False, "none"


def _plugins_from_urls(urls: list[str]) -> dict[str, str | None]:
    plugins: dict[str, str | None] = {}
    for url in urls:
        m = _PLUGIN_PATH_RE.search(url)
        if not m:
            continue
        slug = m.group(1).lower()
        ver = None
        qs = parse_qs(urlparse(url).query)
        vlist = qs.get(_VER_QS_KEY)
        if vlist:
            vm = _VERSION_RE.search(vlist[0])
            if vm:
                ver = ".".join(g for g in vm.groups() if g is not None)
        if slug not in plugins or (ver and not plugins[slug]):
            plugins[slug] = ver
    return plugins


def _themes_from_urls(urls: list[str]) -> dict[str, str | None]:
    themes: dict[str, str | None] = {}
    for url in urls:
        m = _THEME_PATH_RE.search(url)
        if not m:
            continue
        slug = m.group(1).lower()
        ver = None
        qs = parse_qs(urlparse(url).query)
        vlist = qs.get(_VER_QS_KEY)
        if vlist:
            vm = _VERSION_RE.search(vlist[0])
            if vm:
                ver = ".".join(g for g in vm.groups() if g is not None)
        if slug not in themes or (ver and not themes[slug]):
            themes[slug] = ver
    return themes


class WordpressEngine:
    """Passive WordPress fingerprinting and security checks.

    Reports on detection, version disclosure, outdated core, exposed
    XML-RPC, exposed REST API, exposed readme, exposed login URLs, and
    enumerated plugins/themes — all from artifacts already in hand.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not _is_wordpress(artifacts):
            return []

        findings: list[Finding] = []
        page_url = artifacts.url
        meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
        h = {k.lower(): v for k, v in artifacts.response_headers.items()}
        all_links = artifacts.all_links
        asset_urls = artifacts.external_script_urls + artifacts.external_stylesheet_urls

        findings.append(Finding(
            title="WordPress detected",
            description=(
                "The site is running WordPress. WordPress powers roughly 40% of "
                "the public web and is a top-three target for automated attack "
                "bots — most exploitation happens via outdated plugins or "
                "themes rather than core. The findings below cover the things "
                "an attacker would learn about this install in the first 30 "
                "seconds of recon."
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
                "Keep core, every plugin, and every theme on the latest version. "
                "Enable automatic background updates for core and well-trusted "
                "plugins. Remove plugins and themes you no longer use rather "
                "than leaving them deactivated — disabled code can still be "
                "loaded by direct URL."
            ),
            framework=_FA["detected"],
            scanner_engine=_ENGINE,
            metadata={"page_url": page_url},
        ))

        version = (
            _extract_version_from_meta(meta)
            or _extract_version_from_querystrings(artifacts)
        )
        if version:
            findings.append(_version_disclosure_finding(version, page_url, meta))
            outdated, bucket = _is_outdated(version)
            if outdated and bucket == "high":
                findings.append(_outdated_finding(version, page_url, Severity.HIGH, "outdated_high"))
            elif outdated and bucket == "medium":
                findings.append(_outdated_finding(version, page_url, Severity.MEDIUM, "outdated_medium"))

        xmlrpc_refs = [u for u in all_links if "/xmlrpc.php" in u]
        if xmlrpc_refs or "x-pingback" in h:
            findings.append(_xmlrpc_finding(xmlrpc_refs, h, page_url))

        wp_json_refs = [u for u in all_links if "/wp-json" in u]
        if wp_json_refs or any("/wp-json" in v for v in h.values() if isinstance(v, str)):
            findings.append(_wp_json_finding(wp_json_refs, page_url))

        readme_refs = [u for u in all_links if "/readme.html" in u.lower()]
        if readme_refs:
            findings.append(_readme_finding(readme_refs, page_url))

        login_refs = [u for u in all_links if "/wp-admin" in u or "/wp-login.php" in u]
        if login_refs:
            findings.append(_login_exposed_finding(login_refs, page_url))

        plugins = _plugins_from_urls(asset_urls)
        themes = _themes_from_urls(asset_urls)
        if plugins:
            findings.append(_plugin_enum_finding(plugins, themes, page_url))

        return findings


def _detection_evidence_text(artifacts: PageArtifacts) -> str:
    bits: list[str] = []
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    h = {k.lower(): v for k, v in artifacts.response_headers.items()}
    if "wordpress" in meta.get("generator", "").lower():
        bits.append(f'meta generator="{meta["generator"]}"')
    if "wordpress" in h.get("x-powered-by", "").lower():
        bits.append(f'X-Powered-By: {h["x-powered-by"]}')
    wp_assets = [u for u in artifacts.external_script_urls
                 if "/wp-content/" in u or "/wp-includes/" in u][:2]
    if wp_assets:
        bits.append("Asset paths: " + ", ".join(wp_assets))
    return "\n".join(bits) or "(WordPress markers detected)"


def _version_disclosure_finding(version: str, page_url: str, meta: dict[str, str]) -> Finding:
    return Finding(
        title=f"WordPress version disclosed: {version}",
        description=(
            f"The WordPress core version ({version}) is published in the page "
            "source. Knowing the exact version lets an attacker look up the "
            "list of CVEs that apply to it and skip straight to a working "
            "exploit, rather than probing blindly. The leak typically comes "
            "from the `<meta name=\"generator\">` tag and from `?ver=` query "
            "strings appended to core JavaScript and CSS files."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.TECHNOLOGY,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=(
                f'<meta name="generator" content="{meta.get("generator", "")}">'
                if "wordpress" in meta.get("generator", "").lower()
                else f"WordPress {version} (from /wp-includes/ ?ver=)"
            ),
            location=page_url,
            source_engine=_ENGINE,
            extra={"version": version},
        )],
        confidence=0.95,
        remediation=(
            "Remove the generator meta tag (add "
            "`remove_action('wp_head', 'wp_generator')` in the theme's "
            "functions.php). Strip `?ver=` from enqueued assets by hooking "
            "`script_loader_src` / `style_loader_src`. Most security plugins "
            "(Wordfence, iThemes Security, Solid Security) ship this as a "
            "single toggle."
        ),
        framework=_FA["version_disclosure"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "version": version},
    )


def _outdated_finding(version: str, page_url: str, severity: Severity,
                      bucket_key: str) -> Finding:
    is_high = severity == Severity.HIGH
    return Finding(
        title=f"WordPress core is out of date ({version})",
        description=(
            f"This site is running WordPress {version}. The current stable "
            f"branch is {_CURRENT_BRANCH[0]}.{_CURRENT_BRANCH[1]}+. "
            + (
                "An old major version means multiple years of public CVEs "
                "are sitting unpatched, including ones with working exploits "
                "in commodity attack frameworks. Treat this as a known-exploited "
                "exposure until updated."
                if is_high else
                "Older minor versions miss security backports for the most "
                "recent CVEs. The upgrade path is usually low-risk because "
                "core ships backwards-compatible point releases."
            )
        ),
        severity=severity,
        category=FindingCategory.TECHNOLOGY,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=f"Detected WordPress {version}",
            location=page_url,
            source_engine=_ENGINE,
            extra={"version": version,
                   "current_branch": f"{_CURRENT_BRANCH[0]}.{_CURRENT_BRANCH[1]}"},
        )],
        confidence=0.9,
        remediation=(
            "Upgrade WordPress core from the dashboard (Dashboard → Updates) or "
            "via wp-cli (`wp core update`). Back up the database and files "
            "before upgrading a major version. After the upgrade, verify "
            "every active plugin and theme is also on its latest release — "
            "compatibility breaks are the most common reason sites stay on "
            "old WordPress, so identify those blockers and replace or update "
            "the responsible extensions."
        ),
        framework=_FA[bucket_key],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "version": version},
    )


def _xmlrpc_finding(refs: list[str], h: dict[str, str], page_url: str) -> Finding:
    evidence_lines = []
    if refs:
        evidence_lines.append("Links: " + ", ".join(refs[:3]))
    if "x-pingback" in h:
        evidence_lines.append(f"X-Pingback header: {h['x-pingback']}")
    return Finding(
        title="WordPress XML-RPC endpoint exposed",
        description=(
            "The `xmlrpc.php` endpoint is reachable. XML-RPC has two specific "
            "attack uses on WordPress: (1) the `system.multicall` method lets "
            "an attacker try hundreds of username/password combinations per "
            "request, which is much faster than hitting `/wp-login.php` and "
            "much harder for rate limiters to catch; and (2) the pingback "
            "feature can be used to bounce HTTP requests through the site "
            "(distributed denial-of-service amplification). Most modern "
            "WordPress sites don't use XML-RPC for anything."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.HEADER,
            content="\n".join(evidence_lines) or "/xmlrpc.php exposed",
            location=page_url,
            source_engine=_ENGINE,
        )],
        confidence=0.9,
        remediation=(
            "Disable XML-RPC entirely if you don't use the WordPress mobile "
            "app, Jetpack, or remote-publishing tools. Drop the request at "
            "the web server (`location = /xmlrpc.php { deny all; }` in "
            "nginx) or block via .htaccess on Apache. The same setting is a "
            "one-click toggle in most security plugins. If you need XML-RPC, "
            "restrict it to known IPs and disable the `pingback.ping` method."
        ),
        framework=_FA["xmlrpc"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "xmlrpc_links": refs[:5]},
    )


def _wp_json_finding(refs: list[str], page_url: str) -> Finding:
    return Finding(
        title="WordPress REST API (/wp-json/) is publicly reachable",
        description=(
            "References to `/wp-json/` appear in the page (link header or HTML). "
            "The REST API is fine to expose for logged-in editors, but the "
            "default `wp/v2/users` endpoint returns the username list — which "
            "is half of a brute-force attack against `/wp-login.php`. Many "
            "WordPress hardening guides treat /wp-json/wp/v2/users as a top "
            "fingerprinting source for site admins."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.HEADER,
            content="Links: " + ", ".join(refs[:3]) if refs else "REST API referenced",
            location=page_url,
            source_engine=_ENGINE,
        )],
        confidence=0.85,
        remediation=(
            "Restrict unauthenticated access to the users endpoint specifically. "
            "Add a `rest_authentication_errors` filter that rejects "
            "unauthenticated requests to `/wp-json/wp/v2/users`, or use a "
            "security plugin's REST API hardening toggle. Don't disable the "
            "whole REST API — Gutenberg, the block editor, and many plugins "
            "depend on it."
        ),
        framework=_FA["wp_json_exposed"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "wp_json_refs": refs[:5]},
    )


def _readme_finding(refs: list[str], page_url: str) -> Finding:
    return Finding(
        title="WordPress /readme.html is exposed",
        description=(
            "The default `/readme.html` ships with every WordPress install and "
            "contains the exact core version. Even when the generator tag and "
            "asset version strings are stripped, leaving readme.html in place "
            "tells an attacker exactly which CVE list applies to the site."
        ),
        severity=Severity.LOW,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW,
            content="Links: " + ", ".join(refs[:3]),
            location=page_url,
            source_engine=_ENGINE,
        )],
        confidence=0.95,
        remediation=(
            "Delete `readme.html` from the web root (it gets re-created on "
            "every core update, so add the deletion to your deploy script). "
            "Alternatively, deny `/readme.html` at the web server."
        ),
        framework=_FA["readme_exposed"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "readme_refs": refs[:5]},
    )


def _login_exposed_finding(refs: list[str], page_url: str) -> Finding:
    return Finding(
        title="WordPress admin or login URL is linked in the public page",
        description=(
            "Links to `/wp-admin/` or `/wp-login.php` appear in the public "
            "HTML. The login URL is well-known on every WordPress site, so "
            "this isn't a secret to begin with — but actively linking it "
            "(e.g. a 'Login' button in the navigation) advertises the "
            "attack surface and invites credential-stuffing automation."
        ),
        severity=Severity.LOW,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW,
            content="Links: " + ", ".join(refs[:3]),
            location=page_url,
            source_engine=_ENGINE,
        )],
        confidence=0.85,
        remediation=(
            "Don't link the admin URL from the public site. For extra "
            "hardening, move the login URL with a plugin like WPS Hide Login "
            "(this is obscurity, not security — but it cuts attack-bot noise "
            "by 90%+). Enforce strong passwords and two-factor authentication "
            "for every account with edit rights."
        ),
        framework=_FA["login_exposed"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "login_refs": refs[:5]},
    )


def _plugin_enum_finding(plugins: dict[str, str | None],
                         themes: dict[str, str | None],
                         page_url: str) -> Finding:
    versioned = {slug: v for slug, v in plugins.items() if v}
    lines = [
        f"{slug} (version: {v})" if v else slug
        for slug, v in list(plugins.items())[:20]
    ]
    return Finding(
        title=f"WordPress plugin paths leaked ({len(plugins)} plugins identified)",
        description=(
            f"Asset URLs reveal the slugs of {len(plugins)} installed plugins"
            + (f", with version numbers on {len(versioned)} of them" if versioned else "")
            + ". Plugins are the most common WordPress attack vector — known "
            "vulnerabilities in popular plugins (Elementor, WPBakery, Slider "
            "Revolution, etc.) are scanned for continuously by automated bots. "
            "Knowing exactly which plugins are installed (and which versions) "
            "lets an attacker check the CVE database and pick a working exploit "
            "before sending a single probe."
        ),
        severity=Severity.MEDIUM if versioned else Severity.LOW,
        category=FindingCategory.RECON,
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW,
            content="Plugins:\n" + "\n".join(lines),
            location=page_url,
            source_engine=_ENGINE,
            extra={"plugin_count": len(plugins),
                   "versioned_count": len(versioned),
                   "theme_count": len(themes)},
        )],
        confidence=0.9,
        remediation=(
            "Strip `?ver=` from plugin assets (most security plugins offer a "
            "single toggle for this). The plugin slugs themselves can't be "
            "hidden completely without breaking how WordPress loads assets, "
            "but you can remove the most distinctive ones. The more important "
            "fix: audit the plugin list, remove anything you don't actively "
            "use, and put the survivors on auto-update. A 6-month-old vulnerable "
            "plugin is a much bigger problem than a leaked slug."
        ),
        framework=_FA["plugin_enum"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "plugins": plugins, "themes": themes},
    )
