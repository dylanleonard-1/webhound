# WebHound — scanner/webhound/engines/cookies/cookie_scanner.py
# Passive analysis of Set-Cookie response headers.
#
# Safe-mode: reads Set-Cookie headers from HttpResponse only.
# Cookies are never stored, replayed, or modified.

from __future__ import annotations

from dataclasses import dataclass

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "cookie_scanner"


# Cookie name fragments that suggest authentication / session / payment data.
# Used to escalate severity when these cookies lack security attributes.
_SENSITIVE_NAME_FRAGMENTS = (
    "session", "sess", "sid", "auth", "token", "jwt", "bearer", "id_token",
    "access_token", "refresh_token", "csrf", "xsrf", "login", "user",
    "remember", "remember_me", "rememberme", "credential", "secret", "key",
)


# Enterprise metadata per finding kind. Cookie issues primarily map to
# OWASP A07 (Auth Failures) and A05 (Security Misconfiguration), and to
# PCI DSS 8.6.1 (session management requirements).
_FA: dict[str, FrameworkAlignment] = {
    "missing_secure": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-614", "CWE-319"], nist_controls=["SC-8", "SC-23"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", cvss_score=5.9,
        pci_dss=["4.2.1", "8.6.1"], iso_27001=["A.8.24"], soc2=["CC6.7"], hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "missing_httponly": FrameworkAlignment(
        owasp_top10=["A07:2021"], cwe_ids=["CWE-1004"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", cvss_score=5.9,
        pci_dss=["8.6.1"], iso_27001=["A.8.5"], soc2=["CC6.1"], hipaa=["164.312(a)(2)(i)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "missing_samesite": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-352", "CWE-1275"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", cvss_score=4.3,
        pci_dss=["8.6.1"], iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "samesite_none_no_secure": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-352"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", cvss_score=6.5,
        pci_dss=["8.6.1"], iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "samesite_none_with_secure": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-352"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "broad_domain": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1270"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "host_prefix_violation": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1275"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["8.6.1"], iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "secure_prefix_violation": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1275"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["8.6.1"], iso_27001=["A.8.5"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
}


@dataclass
class ParsedCookie:
    """Structured representation of a single Set-Cookie header value."""

    raw: str
    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None   # 'Strict', 'Lax', 'None' (case-preserved)
    domain: str | None = None
    path: str | None = None
    max_age: int | None = None
    expires: str | None = None

    @property
    def is_session_cookie(self) -> bool:
        return self.max_age is None and self.expires is None

    @property
    def has_broad_domain(self) -> bool:
        """True if domain is set to a value that covers subdomains (leading dot)."""
        return bool(self.domain and self.domain.startswith("."))

    @property
    def looks_sensitive(self) -> bool:
        name_lc = self.name.lower()
        return any(f in name_lc for f in _SENSITIVE_NAME_FRAGMENTS)

    @property
    def has_host_prefix(self) -> bool:
        # Per RFC 6265bis __Host- prefix: must have Secure, Path=/, no Domain attr.
        return self.name.startswith("__Host-")

    @property
    def has_secure_prefix(self) -> bool:
        # __Secure- prefix: must have Secure attribute.
        return self.name.startswith("__Secure-")


def parse_set_cookie(raw: str) -> ParsedCookie:
    """Parse a raw Set-Cookie header value into a :class:`ParsedCookie`."""
    parts = [p.strip() for p in raw.split(";")]
    cookie = ParsedCookie(raw=raw, name="", value="")

    # First part is always name=value (or just name).
    if parts:
        first = parts[0]
        if "=" in first:
            name, _, val = first.partition("=")
            cookie.name = name.strip()
            cookie.value = val.strip()
        else:
            cookie.name = first.strip()

    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            cookie.secure = True
        elif lower == "httponly":
            cookie.http_only = True
        elif lower.startswith("samesite="):
            cookie.same_site = part.split("=", 1)[1].strip()
        elif lower.startswith("domain="):
            cookie.domain = part.split("=", 1)[1].strip()
        elif lower.startswith("path="):
            cookie.path = part.split("=", 1)[1].strip()
        elif lower.startswith("max-age="):
            try:
                cookie.max_age = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass
        elif lower.startswith("expires="):
            cookie.expires = part.split("=", 1)[1].strip()

    return cookie


class CookieScannerEngine:
    """Passive analysis of Set-Cookie response headers.

    Checks each cookie for missing security attributes (Secure, HttpOnly,
    SameSite), overly broad domain/path scope, and violations of the
    RFC 6265bis `__Host-` / `__Secure-` prefix rules. Cookies whose name
    suggests session / auth / token content escalate severity on attribute
    gaps.

    Safe-mode: observation only — cookies are never stored, replayed,
    or sent in subsequent requests.
    """

    NAME = _ENGINE

    def analyze(self, response: HttpResponse) -> list[Finding]:
        cookies = _collect_cookies(response)
        if not cookies:
            return []

        findings: list[Finding] = []
        url = response.url
        is_https = url.startswith("https://")

        for cookie in cookies:
            findings.extend(self._check_secure_flag(cookie, url, is_https))
            findings.extend(self._check_httponly_flag(cookie, url))
            findings.extend(self._check_samesite(cookie, url))
            findings.extend(self._check_broad_scope(cookie, url))
            findings.extend(self._check_host_prefix(cookie, url))
            findings.extend(self._check_secure_prefix(cookie, url))

        return findings

    # ------------------------------------------------------------------
    # Secure flag
    # ------------------------------------------------------------------

    def _check_secure_flag(
        self, cookie: ParsedCookie, url: str, is_https: bool
    ) -> list[Finding]:
        if cookie.secure or not is_https:
            return []
        # Escalate severity when the cookie name hints at sensitive content.
        sensitive = cookie.looks_sensitive
        sev = Severity.HIGH if sensitive else Severity.MEDIUM
        ev = _cookie_ev(cookie, url)
        sensitivity_note = (
            "\n\nThe cookie name suggests it carries session or authentication "
            "data — losing it to an HTTP downgrade is a real session-hijack risk."
            if sensitive else ""
        )
        return [_finding(
            title=f"Cookie `{cookie.name}` is missing the Secure flag",
            description=(
                f"The cookie `{cookie.name}` was set on an HTTPS page but doesn't carry "
                "the Secure attribute. That means the browser will happily send it over "
                "plain HTTP if the visitor ever ends up on an HTTP URL of your site — "
                "anyone on their network can read it." + sensitivity_note
                + "\n\nPassive-analysis note: WebHound inspects Set-Cookie response "
                "headers only. Cookies created by JavaScript (document.cookie) after "
                "page load are not covered by this check."
            ),
            severity=sev,
            url=url,
            evidence=ev,
            remediation=f"Add `Secure` to the cookie: `Set-Cookie: {cookie.name}=...; Secure; HttpOnly; SameSite=Lax`",
            framework=_FA["missing_secure"],
        )]

    # ------------------------------------------------------------------
    # HttpOnly flag
    # ------------------------------------------------------------------

    def _check_httponly_flag(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        if cookie.http_only:
            return []
        sensitive = cookie.looks_sensitive
        sev = Severity.HIGH if sensitive else Severity.MEDIUM
        ev = _cookie_ev(cookie, url)
        sensitivity_note = (
            "\n\nThe cookie name suggests it carries a session token. If you ever "
            "ship an XSS bug, an attacker reads this cookie with `document.cookie` "
            "and gets to impersonate the victim. HttpOnly closes that door."
            if sensitive else ""
        )
        return [_finding(
            title=f"Cookie `{cookie.name}` is missing HttpOnly",
            description=(
                f"The cookie `{cookie.name}` can be read by any JavaScript running "
                "on the page. If you ever have a cross-site scripting bug — and most "
                "sites do at least once — the attacker can read the cookie value and "
                "use it." + sensitivity_note
                + "\n\nPassive-analysis note: WebHound inspects Set-Cookie response "
                "headers only. Cookies created by JavaScript (document.cookie) after "
                "page load are not analyzed by this check — those cookies cannot carry "
                "HttpOnly regardless of server intent, so this finding applies only to "
                "the server-set cookie above."
            ),
            severity=sev,
            url=url,
            evidence=ev,
            remediation=f"Add `HttpOnly` to the cookie: `Set-Cookie: {cookie.name}=...; HttpOnly; Secure; SameSite=Lax`",
            framework=_FA["missing_httponly"],
        )]

    # ------------------------------------------------------------------
    # SameSite
    # ------------------------------------------------------------------

    def _check_samesite(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        findings: list[Finding] = []
        ev = _cookie_ev(cookie, url)

        if cookie.same_site is None:
            findings.append(_finding(
                title=f"Cookie `{cookie.name}` has no SameSite attribute",
                description=(
                    f"The cookie `{cookie.name}` doesn't declare a SameSite policy. "
                    "Modern browsers default to `Lax`, which is OK — but the default "
                    "is browser-specific, and explicitly setting it is the modern best "
                    "practice. Without an explicit value, you're depending on browser "
                    "defaults to protect against cross-site request forgery."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    f"Pick a SameSite value and set it explicitly:\n"
                    f"  Set-Cookie: {cookie.name}=...; SameSite=Lax; Secure; HttpOnly\n"
                    "Use `SameSite=Strict` for the tightest protection, `Lax` for the "
                    "modern default, or `None; Secure` only when you intentionally use "
                    "the cookie in cross-site contexts (e.g. embedded checkout)."
                ),
                framework=_FA["missing_samesite"],
            ))
        elif cookie.same_site.lower() == "none":
            if not cookie.secure:
                findings.append(_finding(
                    title=f"Cookie `{cookie.name}`: SameSite=None without Secure (browsers reject this)",
                    description=(
                        f"The cookie `{cookie.name}` is set with `SameSite=None` but "
                        "without the Secure attribute. Modern browsers reject this "
                        "combination outright — the cookie gets dropped, which usually "
                        "shows up as 'my session keeps logging me out'. It's also a "
                        "configuration smell that often hides bigger auth bugs."
                    ),
                    severity=Severity.HIGH,
                    url=url,
                    evidence=ev,
                    remediation=(
                        f"Either add `Secure` (and only do this if you genuinely need "
                        "cross-site cookie sending), or change to `SameSite=Lax`:\n"
                        f"  Set-Cookie: {cookie.name}=...; SameSite=None; Secure; HttpOnly\n"
                        f"  Set-Cookie: {cookie.name}=...; SameSite=Lax;  Secure; HttpOnly"
                    ),
                    framework=_FA["samesite_none_no_secure"],
                ))
            else:
                findings.append(_finding(
                    title=f"Cookie `{cookie.name}` allows cross-site use (SameSite=None)",
                    description=(
                        f"The cookie `{cookie.name}` is explicitly configured for "
                        "cross-site delivery (`SameSite=None; Secure`). That's fine "
                        "for embedded payment widgets and similar — but verify this "
                        "cookie doesn't carry session tokens. Cross-site delivery "
                        "removes one of the CSRF safety nets browsers give you."
                    ),
                    severity=Severity.LOW,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "If cross-site use is required (embedded iframes, etc), no "
                        "action needed. If not, switch to `SameSite=Lax` or `Strict`."
                    ),
                    framework=_FA["samesite_none_with_secure"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Broad domain scope
    # ------------------------------------------------------------------

    def _check_broad_scope(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        if not cookie.has_broad_domain:
            return []
        ev = _cookie_ev(cookie, url)
        return [_finding(
            title=f"Cookie `{cookie.name}` is shared with every subdomain",
            description=(
                f"The cookie `{cookie.name}` is scoped to `{cookie.domain}` — the "
                "leading dot tells browsers to send it to every subdomain of your "
                "domain. If any subdomain ever gets compromised (especially via a "
                "shared hosting provider, dangling CNAME, or third-party app), the "
                "attacker can read this cookie even without touching your main site."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Scope cookies to the narrowest domain that needs them. Default to "
                "omitting the `Domain` attribute entirely so the cookie is only sent "
                "to the exact host that set it."
            ),
            framework=_FA["broad_domain"],
        )]

    # ------------------------------------------------------------------
    # __Host- prefix validation (RFC 6265bis §4.1.3.2)
    # ------------------------------------------------------------------

    def _check_host_prefix(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        if not cookie.has_host_prefix:
            return []
        violations: list[str] = []
        if not cookie.secure:
            violations.append("missing Secure flag")
        if cookie.domain:
            violations.append(f"Domain attribute set ({cookie.domain})")
        if cookie.path != "/":
            violations.append(f"Path is `{cookie.path or '<unset>'}` (must be `/`)")
        if not violations:
            return []
        ev = _cookie_ev(cookie, url)
        return [_finding(
            title=f"Cookie `{cookie.name}` violates __Host- prefix rules",
            description=(
                f"The cookie name starts with `__Host-`, which is a strict prefix "
                "browsers enforce: the cookie MUST be set with `Secure`, MUST be "
                "set to `Path=/`, and MUST NOT have a Domain attribute. This one "
                f"fails on: {', '.join(violations)}. Browsers will silently drop "
                "the cookie — so whatever you stored in it isn't reaching the "
                "browser back."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                f"Fix the attributes to match the prefix's contract:\n"
                f"  Set-Cookie: {cookie.name}=...; Secure; Path=/; HttpOnly; SameSite=Lax\n"
                "Or, if you don't actually need the strict guarantees the prefix "
                "provides, just rename the cookie to not start with `__Host-`."
            ),
            framework=_FA["host_prefix_violation"],
        )]

    # ------------------------------------------------------------------
    # __Secure- prefix validation (RFC 6265bis §4.1.3.1)
    # ------------------------------------------------------------------

    def _check_secure_prefix(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        # __Secure- must be set with the Secure flag. Anything else is dropped.
        if not cookie.has_secure_prefix or cookie.secure:
            return []
        ev = _cookie_ev(cookie, url)
        return [_finding(
            title=f"Cookie `{cookie.name}` uses __Secure- prefix without Secure flag",
            description=(
                f"The cookie name starts with `__Secure-`, which tells browsers to "
                "REQUIRE the Secure attribute. This cookie doesn't have it, so the "
                "browser silently drops the cookie. The site won't see it on the "
                "way back."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                f"Add the Secure attribute:\n"
                f"  Set-Cookie: {cookie.name}=...; Secure; HttpOnly; SameSite=Lax\n"
                "Or rename the cookie if you don't want to require HTTPS for it."
            ),
            framework=_FA["secure_prefix_violation"],
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_cookies(response: HttpResponse) -> list[ParsedCookie]:
    cookies: list[ParsedCookie] = []
    for key, value in response.headers.items():
        if key.lower() == "set-cookie" and value.strip():
            # httpx joins multiple Set-Cookie headers with newlines; some
            # other clients use comma separation. Split on both to handle
            # responses that genuinely set multiple cookies per response.
            for line in value.replace("\r\n", "\n").split("\n"):
                line = line.strip()
                if line:
                    cookies.append(parse_set_cookie(line))
    return cookies


def _cookie_ev(cookie: ParsedCookie, url: str) -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.COOKIE,
        content=cookie.raw,
        location=url,
        source_engine=_ENGINE,
        extra={"cookie_name": cookie.name},
    )


def _finding(
    title: str,
    description: str,
    severity: Severity,
    url: str,
    evidence: Evidence,
    remediation: str | None = None,
    framework: FrameworkAlignment | None = None,
    confidence: float = 1.0,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=FindingCategory.COOKIE,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=framework or FrameworkAlignment(),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
