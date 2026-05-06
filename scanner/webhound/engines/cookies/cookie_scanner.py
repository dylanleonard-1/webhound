# WebHound — scanner/webhound/engines/cookies/cookie_scanner.py
# Passive analysis of Set-Cookie response headers.
#
# Safe-mode: reads Set-Cookie headers from HttpResponse only.
# Cookies are never stored, replayed, or modified.

from __future__ import annotations

from dataclasses import dataclass, field

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "cookie_scanner"


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
    SameSite) and overly broad domain/path scope.

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

        return findings

    # ------------------------------------------------------------------
    # Secure flag
    # ------------------------------------------------------------------

    def _check_secure_flag(
        self, cookie: ParsedCookie, url: str, is_https: bool
    ) -> list[Finding]:
        if cookie.secure or not is_https:
            return []
        ev = _cookie_ev(cookie, url)
        return [_finding(
            title=f"Cookie '{cookie.name}' missing Secure flag",
            description=(
                f"The cookie '{cookie.name}' is set without the Secure attribute "
                "on an HTTPS page. It may be transmitted over unencrypted HTTP "
                "connections (e.g., after a redirect), allowing interception."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=f"Add the 'Secure' attribute: Set-Cookie: {cookie.name}=...; Secure",
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-614"],
                nist_controls=["SC-8"],
            ),
        )]

    # ------------------------------------------------------------------
    # HttpOnly flag
    # ------------------------------------------------------------------

    def _check_httponly_flag(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        if cookie.http_only:
            return []
        ev = _cookie_ev(cookie, url)
        return [_finding(
            title=f"Cookie '{cookie.name}' missing HttpOnly flag",
            description=(
                f"The cookie '{cookie.name}' is accessible via JavaScript "
                "(HttpOnly is not set). If an XSS vulnerability exists, an attacker "
                "can read this cookie using document.cookie."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=f"Add 'HttpOnly': Set-Cookie: {cookie.name}=...; HttpOnly",
            framework=FrameworkAlignment(
                owasp_top10=["A07:2021"],
                cwe_ids=["CWE-1004"],
                nist_controls=["SC-8"],
            ),
        )]

    # ------------------------------------------------------------------
    # SameSite
    # ------------------------------------------------------------------

    def _check_samesite(self, cookie: ParsedCookie, url: str) -> list[Finding]:
        findings: list[Finding] = []
        ev = _cookie_ev(cookie, url)

        if cookie.same_site is None:
            findings.append(_finding(
                title=f"Cookie '{cookie.name}' missing SameSite attribute",
                description=(
                    f"The cookie '{cookie.name}' has no SameSite attribute. "
                    "Browsers default to 'Lax' in modern implementations, but "
                    "omitting SameSite may allow the cookie to be sent in "
                    "cross-site POST requests on older browsers, risking CSRF."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    f"Add SameSite: Set-Cookie: {cookie.name}=...; "
                    "SameSite=Strict (or Lax)"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-352"],
                    nist_controls=["SC-8"],
                ),
            ))
        elif cookie.same_site.lower() == "none":
            if not cookie.secure:
                findings.append(_finding(
                    title=f"Cookie '{cookie.name}': SameSite=None without Secure",
                    description=(
                        f"The cookie '{cookie.name}' sets SameSite=None without "
                        "the Secure attribute. Browsers reject this combination — "
                        "the cookie will be dropped. This indicates a configuration "
                        "error."
                    ),
                    severity=Severity.HIGH,
                    url=url,
                    evidence=ev,
                    remediation=(
                        f"Add the Secure flag: Set-Cookie: {cookie.name}=...; "
                        "SameSite=None; Secure"
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-352"],
                        nist_controls=["SC-8"],
                    ),
                ))
            else:
                findings.append(_finding(
                    title=f"Cookie '{cookie.name}' set for cross-site use (SameSite=None)",
                    description=(
                        f"The cookie '{cookie.name}' explicitly allows cross-site "
                        "sending (SameSite=None; Secure). Verify this is intentional "
                        "and the cookie does not carry sensitive authentication data."
                    ),
                    severity=Severity.LOW,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "If cross-site use is not required, use SameSite=Strict "
                        "or SameSite=Lax instead."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-352"],
                        nist_controls=["SC-8"],
                    ),
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
            title=f"Cookie '{cookie.name}' has broad domain scope",
            description=(
                f"The cookie '{cookie.name}' is scoped to '{cookie.domain}' "
                "(leading dot indicates all subdomains). This means every subdomain "
                "receives the cookie, increasing the attack surface if any subdomain "
                "is compromised."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Scope cookies to the narrowest necessary domain. "
                "Avoid Domain= attribute unless subdomain sharing is required."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-1270"],
                nist_controls=["SC-8"],
            ),
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_cookies(response: HttpResponse) -> list[ParsedCookie]:
    cookies: list[ParsedCookie] = []
    for key, value in response.headers.items():
        if key.lower() == "set-cookie" and value.strip():
            cookies.append(parse_set_cookie(value))
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
