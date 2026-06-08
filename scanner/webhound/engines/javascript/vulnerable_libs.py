# WebHound — scanner/webhound/engines/javascript/vulnerable_libs.py
# Detect known-vulnerable JavaScript libraries by their CDN URL.
#
# Safe-mode: reads pre-collected external script URLs only.
# No HTTP fetches, no execution.
#
# Detection happens in two stages:
#   1. Parse the URL to recover the (library_name, version) pair using common
#      CDN URL conventions (jsdelivr, unpkg, cdnjs, googleapis, bootstrapcdn,
#      jquery.com).
#   2. Look up the library in a curated rule table and decide whether the
#      version falls inside a published vulnerable range.
# We deliberately keep the rule set small and high-confidence — only public
# CVEs whose version is a strong signal. Anything that requires checking
# the actual script body belongs elsewhere.

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "vulnerable_libs"


# ---------------------------------------------------------------------------
# CDN URL parsing
# ---------------------------------------------------------------------------

# Patterns that recover (library, version) from common CDN URL conventions.
# Library names are lower-cased before lookup. The order matters: more-specific
# patterns first.

_CDN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # jsdelivr / unpkg style: /{lib}@{version}/...
    re.compile(r"/(?:npm|gh)/(?P<lib>[a-z0-9_\-.]+(?:/[a-z0-9_\-.]+)?)@(?P<ver>\d+(?:\.\d+)+)", re.I),
    re.compile(r"/(?P<lib>[a-z0-9_\-.]+(?:/[a-z0-9_\-.]+)?)@(?P<ver>\d+(?:\.\d+)+)", re.I),
    # cdnjs / googleapis: /libs/{lib}/{version}/
    re.compile(r"/(?:libs|ajax/libs)/(?P<lib>[a-z0-9_\-.]+)/(?P<ver>\d+(?:\.\d+)+)/", re.I),
    # bootstrapcdn: /{lib}/{version}/
    re.compile(r"/(?P<lib>bootstrap|jquery|jquery-ui|angularjs?|moment|lodash|dompurify|prototype)/(?P<ver>\d+(?:\.\d+)+)/", re.I),
    # jquery.com style: /{lib}-{version}.min.js
    re.compile(r"/(?P<lib>jquery|jquery-ui|jquery\.ui)[\-_]v?(?P<ver>\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I),
)

# Library names extracted from URLs are normalised here.
_LIB_ALIASES: dict[str, str] = {
    "angularjs": "angularjs",
    "angular.js": "angularjs",
    "angular": "angularjs",
    "jquery-ui": "jquery-ui",
    "jqueryui": "jquery-ui",
    "jquery.ui": "jquery-ui",
    "lodash.js": "lodash",
    "moment.js": "moment",
    "prototype.js": "prototype",
    "dompurify-bundle": "dompurify",
}


def _parse_cdn_url(url: str) -> tuple[str, str] | None:
    """Extract `(library, version)` from a CDN script URL, or None."""
    if not url:
        return None
    parsed = urlparse(url)
    full = parsed.path
    for pattern in _CDN_PATTERNS:
        m = pattern.search(full)
        if not m:
            continue
        lib = m.group("lib").lower()
        # Strip nested path like "@scope/name" -> "name" for npm-scoped libs.
        if "/" in lib:
            lib = lib.split("/")[-1]
        lib = _LIB_ALIASES.get(lib, lib)
        ver = m.group("ver")
        return lib, ver
    return None


# ---------------------------------------------------------------------------
# Vulnerable-version rules — keyed by normalised library name
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    name: str               # Human-readable library name
    safe_at: tuple[int, ...]  # First version that is NOT vulnerable
    cves: list[str]
    severity: Severity
    headline: str
    summary: str


def _v(version: str) -> tuple[int, ...]:
    """Parse a version string like '3.4.1' into (3, 4, 1)."""
    return tuple(int(p) for p in re.findall(r"\d+", version)) or (0,)


_RULES: dict[str, _Rule] = {
    "jquery": _Rule(
        name="jQuery",
        safe_at=_v("3.5.0"),
        cves=["CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358", "CVE-2015-9251"],
        severity=Severity.HIGH,
        headline="jQuery version is vulnerable to XSS",
        summary=(
            "jQuery versions below 3.5.0 are vulnerable to cross-site scripting "
            "through `.html()`, `.append()`, and related DOM helpers. The "
            "vulnerable code paths accept HTML strings that contain a script "
            "tag with carefully placed whitespace; older jQuery executes them."
        ),
    ),
    "angularjs": _Rule(
        name="AngularJS",
        safe_at=_v("9999.0.0"),  # AngularJS 1.x is EOL — every version is unsafe
        cves=["CVE-2024-21490", "CVE-2023-26116", "CVE-2023-26117", "CVE-2023-26118"],
        severity=Severity.HIGH,
        headline="AngularJS is end-of-life — every version has open CVEs",
        summary=(
            "AngularJS 1.x reached end-of-life in December 2021. Google no "
            "longer ships patches, and multiple public CVEs (ReDoS, prototype "
            "pollution, expression injection) remain unfixed. Migration to a "
            "maintained framework is the only real fix."
        ),
    ),
    "lodash": _Rule(
        name="lodash",
        safe_at=_v("4.17.21"),
        cves=["CVE-2021-23337", "CVE-2020-8203", "CVE-2019-10744"],
        severity=Severity.HIGH,
        headline="lodash version is vulnerable to prototype pollution / command injection",
        summary=(
            "lodash before 4.17.21 has three high-impact CVEs: prototype "
            "pollution via `_.zipObjectDeep` and `_.merge`, plus command "
            "injection in `_.template`. Patched in 4.17.21."
        ),
    ),
    "jquery-ui": _Rule(
        name="jQuery UI",
        safe_at=_v("1.13.2"),
        cves=["CVE-2022-31160", "CVE-2021-41184", "CVE-2021-41183", "CVE-2021-41182", "CVE-2016-7103"],
        severity=Severity.MEDIUM,
        headline="jQuery UI version has multiple XSS vulnerabilities",
        summary=(
            "jQuery UI before 1.13.2 has XSS bugs in the .tooltip(), .dialog(), "
            "and .checkboxradio() widgets. Update to 1.13.2 or replace with a "
            "maintained alternative."
        ),
    ),
    "bootstrap": _Rule(
        name="Bootstrap",
        safe_at=_v("5.0.0"),  # Bootstrap 3.x EOL since 2019, 4.x in maintenance
        cves=["CVE-2019-8331", "CVE-2018-14041", "CVE-2018-14040", "CVE-2018-14042"],
        severity=Severity.MEDIUM,
        headline="Bootstrap version has XSS vulnerabilities",
        summary=(
            "Bootstrap before 3.4.0 (and 4.x before 4.3.1) has XSS bugs in "
            "tooltips, data-target, and the collapse / scrollspy plugins. "
            "Bootstrap 3 reached EOL in 2019 — upgrade to 5.x."
        ),
    ),
    "prototype": _Rule(
        name="prototype.js",
        safe_at=_v("9999.0.0"),  # all versions — library is abandoned
        cves=[],
        severity=Severity.MEDIUM,
        headline="prototype.js is abandoned — last release was 2015",
        summary=(
            "prototype.js hasn't shipped a release since 2015. It modifies "
            "built-in object prototypes globally, conflicting with modern code "
            "and creating supply-chain risk. Migrate off it."
        ),
    ),
    "moment": _Rule(
        name="Moment.js",
        safe_at=_v("2.29.4"),
        cves=["CVE-2022-31129", "CVE-2022-24785"],
        severity=Severity.MEDIUM,
        headline="Moment.js version has known DoS vulnerabilities",
        summary=(
            "Moment.js before 2.29.4 is vulnerable to ReDoS via crafted date "
            "strings (CVE-2022-31129) and a path-traversal in locale loading "
            "(CVE-2022-24785). Moment is also in maintenance mode — consider "
            "Day.js, Luxon, or the native Intl.DateTimeFormat."
        ),
    ),
    "dompurify": _Rule(
        name="DOMPurify",
        safe_at=_v("3.0.0"),
        cves=["CVE-2024-45801", "CVE-2024-47875", "CVE-2022-23631"],
        severity=Severity.HIGH,
        headline="DOMPurify version has known sanitizer bypasses",
        summary=(
            "DOMPurify before 3.0.0 has several published sanitizer bypasses. "
            "This is the library most sites rely on for HTML sanitization, so "
            "a bypass undoes XSS protection across the entire site."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class VulnerableLibsEngine:
    """Detect known-vulnerable JavaScript libraries from external script URLs.

    Detection is URL-based and conservative — we surface a finding only when
    the URL encodes a recognised library name AND version, and the version
    is below the published patched release.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        """Per-page entry point: scan one page's external script srcs."""
        urls = [
            s.src for s in artifacts.scripts
            if s.is_external and s.src
        ]
        return self.analyze_script_urls(urls, page_url=artifacts.url)

    def analyze_script_urls(
        self, script_urls: list[str], page_url: str = "",
    ) -> list[Finding]:
        """Scan an arbitrary inventory of script URLs.

        Used by the orchestrator's scan-wide pass to feed static,
        rendered-DOM, and browser-loaded script URLs (including dynamic
        chunks) through one deduplicated detection run. Non-CDN or
        unversioned URLs are silently ignored — ``_parse_cdn_url`` only
        matches recognised ``(library, version)`` conventions.
        """
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()  # (library, version) dedup

        for src in script_urls:
            if not src:
                continue
            parsed = _parse_cdn_url(src)
            if not parsed:
                continue
            lib, version = parsed
            rule = _RULES.get(lib)
            if not rule:
                continue
            if _v(version) >= rule.safe_at:
                continue
            key = (rule.name, version)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._build(rule, src, version, page_url))

        return findings

    def _build(self, rule: _Rule, src_url: str, version: str, page_url: str) -> Finding:
        cve_str = ", ".join(rule.cves[:3]) if rule.cves else "no specific CVE — library is unmaintained"
        ev = Evidence(
            evidence_type=EvidenceType.JAVASCRIPT,
            content=f"{rule.name} {version} loaded from: {src_url}",
            location=page_url,
            source_engine=_ENGINE,
            extra={
                "library": rule.name,
                "version": version,
                "src": src_url,
                "cves": rule.cves,
            },
        )
        return Finding(
            title=f"{rule.headline} ({rule.name} {version})",
            description=(
                f"Your site loads {rule.name} version {version} from `{src_url}`. "
                f"{rule.summary} "
                f"(Tracked CVEs: {cve_str}.)"
            ),
            severity=rule.severity,
            category=FindingCategory.JAVASCRIPT,
            evidence=[ev],
            confidence=0.9,
            remediation=(
                f"Update {rule.name} to the latest patched version. If you load "
                "it from a CDN URL, change the version number in the URL and "
                "add an `integrity=` SRI hash for the new file. If you can't "
                "upgrade (legacy code), pin to the latest patch release of "
                "your major version and document the residual risk."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A06:2021"],  # Vulnerable and Outdated Components
                cwe_ids=["CWE-1395", "CWE-1104"],
                nist_controls=["SI-2", "SA-12"],
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                cvss_score=6.1 if rule.severity == Severity.HIGH else 4.7,
                pci_dss=["6.3.2", "6.3.3"],
                iso_27001=["A.8.8", "A.8.28"],
                soc2=["CC7.1"],
                exploitability=Exploitability.PRACTICAL if rule.cves else Exploitability.THEORETICAL,
            ),
            scanner_engine=_ENGINE,
            metadata={"url": page_url, "library": rule.name, "version": version},
        )
