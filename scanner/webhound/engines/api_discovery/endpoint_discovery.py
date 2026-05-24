# WebHound — scanner/webhound/engines/api_discovery/endpoint_discovery.py
# Passive API surface enumeration.
#
# Inventories every backend endpoint the page references — REST routes,
# GraphQL, WebSockets, SOAP — and flags the ones that shouldn't be in
# public client code (internal/admin endpoints, API keys in query
# strings, insecure WebSockets, hardcoded internal infrastructure).
#
# Safe-mode: reads pre-extracted PageArtifacts only. No probing of any
# endpoint we discover — that's intentional. The orchestrator separately
# probes a small allow-list of paths in sensitive_paths.py.

from __future__ import annotations

import ipaddress
import re
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

_ENGINE = "endpoint_discovery"

# REST-style API path. Matches /api/, /v1/, /v2/, /rest/, /services/ at path root.
_REST_RE = re.compile(r"^/?(?:api|rest|v\d+|services?)(?:/|$)", re.I)

_GRAPHQL_RE = re.compile(r"(?:/graphql\b|/graphiql\b|/__graphql\b|\?__schema\b)", re.I)

_AUTH_RE = re.compile(
    r"/(?:oauth\d?|sso|saml|openid|auth|login|signin|signup|register|"
    r"token|refresh|logout|session|otp|mfa|2fa|password[-_]?reset|forgot[-_]?password)\b",
    re.I,
)

_INTERNAL_ADMIN_RE = re.compile(
    r"/(?:admin|administrator|internal|backend|sysadmin|staff|"
    r"superuser|dashboard/admin|api/admin|admin/api|"
    r"api/internal|internal/api|"
    r"_admin|_internal|_backstage|_management)\b",
    re.I,
)

_UPLOAD_RE = re.compile(
    r"/(?:upload|uploads?|files?|attach(?:ment)?s?|media/upload|"
    r"images?/upload|documents?/upload|import)\b",
    re.I,
)

_PII_RE = re.compile(
    r"/(?:users?|customers?|patients?|members?|accounts?|profiles?|"
    r"orders?|payments?|billing|invoices?|subscriptions?|"
    r"addresses?|ssn|tax[-_]?id|medical|health)\b",
    re.I,
)

_API_SPEC_RE = re.compile(
    r"/(?:swagger(?:[-_.]?(?:ui|json|yaml))?|openapi(?:\.(?:json|yaml))?|"
    r"api[-_]?docs?|redoc|rapidoc|api[-_]?spec|"
    r"\.well-known/openapi)\b",
    re.I,
)

_SOAP_RE = re.compile(r"\?wsdl\b|/services/[A-Za-z0-9_\-]+\?wsdl", re.I)

_TOKEN_QS_KEYS = (
    "api_key", "apikey", "access_token", "accesstoken", "auth_token",
    "authtoken", "token", "bearer", "secret", "session", "session_id",
    "sessionid", "id_token", "refresh_token", "x-api-key", "key",
    "password", "passwd",
)
_TOKEN_QS_RE = re.compile(
    r"[?&](" + "|".join(re.escape(k) for k in _TOKEN_QS_KEYS) + r")=([^&\s\"'<>]{8,})",
    re.I,
)

_INTERNAL_HOSTNAMES_RE = re.compile(
    r"(?:"
    r"localhost|"
    r"\.local\b|"
    r"\.internal\b|"
    r"\.lan\b|"
    r"\.corp\b|"
    r"\.intranet\b|"
    r"\.elb\.amazonaws\.com|"
    r"\.execute-api\.[a-z0-9\-]+\.amazonaws\.com|"
    r"\.s3-website[.-][\w-]+\.amazonaws\.com|"
    r"\.compute-\d+\.amazonaws\.com|"
    r"\.appspot\.internal|"
    r"\.azurewebsites\.net|"
    r"\.azure\.com|"
    r"\.cloudfunctions\.net|"
    r"\.run\.app"
    r")",
    re.I,
)

_ABS_URL_RE = re.compile(
    r"\bhttps?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-/\.~%?&=:]+", re.I
)
_PATH_LITERAL_RE = re.compile(
    r'["\'`](/(?:api|rest|v\d+|services?|graphql|admin|internal)/[A-Za-z0-9_\-/\.~%?&=:]+)["\'`]',
    re.I,
)


_FA: dict[str, FrameworkAlignment] = {
    "inventory": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-200"],
        nist_controls=["CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=["6.3.3"],
        iso_27001=["A.8.8", "A.8.9"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "graphql_exposed": FrameworkAlignment(
        owasp_top10=["A05:2021", "A01:2021"],
        cwe_ids=["CWE-200", "CWE-668"],
        nist_controls=["AC-3", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.9", "A.8.28"],
        soc2=["CC6.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "internal_api_in_client": FrameworkAlignment(
        owasp_top10=["A01:2021", "A05:2021"],
        cwe_ids=["CWE-200", "CWE-285", "CWE-749"],
        nist_controls=["AC-3", "AC-4", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.6,
        pci_dss=["6.2.4", "7.2.1"],
        iso_27001=["A.5.15", "A.8.9"],
        soc2=["CC6.1", "CC6.3"],
        hipaa=["164.312(a)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "token_in_url": FrameworkAlignment(
        owasp_top10=["A02:2021", "A07:2021"],
        cwe_ids=["CWE-598", "CWE-200", "CWE-522"],
        nist_controls=["IA-5", "SC-8", "AU-9"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        pci_dss=["3.5.1", "8.3.1"],
        iso_27001=["A.5.17", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=["164.312(d)", "164.312(e)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "insecure_websocket": FrameworkAlignment(
        owasp_top10=["A02:2021"],
        cwe_ids=["CWE-319", "CWE-523"],
        nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cvss_score=8.2,
        pci_dss=["4.2.1"],
        iso_27001=["A.8.20"],
        soc2=["CC6.1"],
        hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "api_spec_exposed": FrameworkAlignment(
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
    "internal_infra_leaked": FrameworkAlignment(
        owasp_top10=["A05:2021", "A01:2021"],
        cwe_ids=["CWE-200", "CWE-668"],
        nist_controls=["CM-7", "AC-3", "SC-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=6.5,
        pci_dss=["1.2.1", "6.2.4"],
        iso_27001=["A.5.14", "A.8.9", "A.8.22"],
        soc2=["CC6.6", "CC6.7"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
}


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _classify(url: str) -> set[str]:
    tags: set[str] = set()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    qs = "?" + (parsed.query or "")
    host = (parsed.hostname or "").lower()

    if scheme in ("ws", "wss"):
        tags.add("websocket")
        if scheme == "ws":
            tags.add("insecure_websocket")
    if _GRAPHQL_RE.search(path) or _GRAPHQL_RE.search(qs):
        tags.add("graphql")
    if _SOAP_RE.search(url):
        tags.add("soap")
    if _REST_RE.match(path) or "/api/" in path or "/v1/" in path or "/v2/" in path:
        tags.add("rest")
    if _AUTH_RE.search(path):
        tags.add("auth")
    if _INTERNAL_ADMIN_RE.search(path):
        tags.add("internal_admin")
    if _UPLOAD_RE.search(path):
        tags.add("upload")
    if _PII_RE.search(path):
        tags.add("pii")
    if _API_SPEC_RE.search(path):
        tags.add("api_spec")
    if _TOKEN_QS_RE.search(url):
        tags.add("token_in_url")
    if host and (_is_private_ip(host) or _INTERNAL_HOSTNAMES_RE.search(host)):
        tags.add("internal_infra")
    return tags


def _gather_endpoints(artifacts: PageArtifacts) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in artifacts.inline_js_request_urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    for f in artifacts.forms:
        if f.action_url and f.action_url not in seen:
            seen.add(f.action_url)
            out.append(f.action_url)
    for body in artifacts.inline_scripts:
        if not body:
            continue
        for m in _PATH_LITERAL_RE.finditer(body):
            u = m.group(1)
            if u not in seen:
                seen.add(u)
                out.append(u)
        for m in _ABS_URL_RE.finditer(body):
            u = m.group(0)
            if any(u.lower().endswith(ext) for ext in (
                ".png", ".jpg", ".jpeg", ".gif", ".css", ".woff",
                ".woff2", ".svg", ".ico", ".webp",
            )):
                continue
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def _summarize(urls: list[str], limit: int = 12) -> str:
    head = urls[:limit]
    tail = f" (+{len(urls) - limit} more)" if len(urls) > limit else ""
    return "\n".join(head) + tail


class EndpointDiscoveryEngine:
    """Passive API surface enumeration and risk surfacing.

    Inventories every backend endpoint referenced by the page (fetch /
    XMLHttpRequest / WebSocket targets, form actions, hardcoded URLs in
    inline scripts), classifies each by API style and risk surface, and
    emits findings for the patterns that warrant attention — internal /
    admin endpoints in public client code, API keys in URL query
    strings, insecure WebSockets, exposed API spec documents, and
    references to internal infrastructure hostnames.

    No endpoint is probed. Active discovery of unlisted paths happens
    in the sensitive_paths engine against a fixed allow-list.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        endpoints = _gather_endpoints(artifacts)
        if not endpoints:
            return []

        page_url = artifacts.url
        page_host = _hostname(page_url)
        page_scheme = (urlparse(page_url).scheme or "").lower()

        by_tag: dict[str, list[str]] = {}
        for url in endpoints:
            for tag in _classify(url):
                by_tag.setdefault(tag, []).append(url)

        findings: list[Finding] = []

        same_origin = [u for u in endpoints
                       if not _hostname(u) or _hostname(u) == page_host]
        cross_origin = [u for u in endpoints
                        if _hostname(u) and _hostname(u) != page_host]
        rest = by_tag.get("rest", [])
        graphql = by_tag.get("graphql", [])
        ws = by_tag.get("websocket", [])
        soap = by_tag.get("soap", [])

        findings.append(Finding(
            title=f"API surface mapped: {len(endpoints)} endpoint reference(s)",
            description=(
                "The page references the following backend endpoints in "
                f"client-side code: {len(rest)} REST, {len(graphql)} GraphQL, "
                f"{len(ws)} WebSocket, {len(soap)} SOAP. {len(same_origin)} "
                f"are on the same origin, {len(cross_origin)} call out to "
                "different hosts. This finding is informational — it's the "
                "raw inventory an attacker would build by browsing the site "
                "and watching the network tab. The companion findings below "
                "flag the specific patterns that warrant attention."
            ),
            severity=Severity.INFO,
            category=FindingCategory.API,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=_summarize(endpoints),
                location=page_url,
                source_engine=_ENGINE,
                extra={
                    "endpoint_count": len(endpoints),
                    "rest_count": len(rest),
                    "graphql_count": len(graphql),
                    "websocket_count": len(ws),
                    "soap_count": len(soap),
                    "same_origin_count": len(same_origin),
                    "cross_origin_count": len(cross_origin),
                },
            )],
            confidence=0.9,
            remediation=(
                "Maintain an up-to-date inventory of every API your site "
                "depends on, internal and third-party. For each cross-origin "
                "destination, document the data sent, the data received, "
                "and the vendor's security posture (SOC 2, ISO 27001, etc). "
                "When deprecating endpoints, remove the client-side "
                "references first so attackers can't enumerate ghost routes."
            ),
            framework=_FA["inventory"],
            scanner_engine=_ENGINE,
            metadata={
                "page_url": page_url,
                "endpoints": endpoints[:50],
                "tag_counts": {k: len(v) for k, v in by_tag.items()},
            },
        ))

        if graphql:
            findings.append(Finding(
                title=f"GraphQL endpoint referenced in client code ({len(graphql)})",
                description=(
                    f"The page calls a GraphQL endpoint: {graphql[0]}. "
                    "GraphQL is fine to expose — that's the design — but two "
                    "specific GraphQL misconfigurations show up constantly: "
                    "(1) leaving introspection (`__schema`) enabled in "
                    "production, which gives attackers the complete data "
                    "model; (2) failing to put depth-limits or "
                    "cost-limits on queries, which lets a single malicious "
                    "query exhaust the database. Neither is visible from a "
                    "passive scan — both need to be confirmed against the "
                    "running server."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="GraphQL endpoints:\n" + "\n".join(graphql[:5]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.8,
                remediation=(
                    "On the GraphQL server: disable introspection in production "
                    "(`introspection: false` in Apollo Server, or remove the "
                    "`GraphiQL` middleware). Add a query-depth limit "
                    "(`graphql-depth-limit`) and a query-cost limit "
                    "(`graphql-cost-analysis`). Require authentication for "
                    "non-public queries. Log and rate-limit per-IP."
                ),
                framework=_FA["graphql_exposed"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "graphql_endpoints": graphql},
            ))

        internal = by_tag.get("internal_admin", [])
        if internal:
            findings.append(Finding(
                title=f"Internal or admin API referenced from public page ({len(internal)})",
                description=(
                    "The page contains references to internal- or admin-flavoured "
                    f"API paths: {internal[0]}"
                    + (f" (and {len(internal) - 1} more)" if len(internal) > 1 else "")
                    + ". Public client JavaScript shouldn't even know these "
                    "endpoints exist — an attacker who finds them can probe "
                    "them directly. The risk depends on whether the endpoint "
                    "actually enforces server-side authorisation: if the only "
                    "thing keeping a regular user out of `/api/admin/users` is "
                    "the fact that the UI doesn't display a link to it, then "
                    "discovering this URL is the entire exploit."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="Internal/admin endpoints referenced:\n" +
                            "\n".join(internal[:10]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.85,
                remediation=(
                    "Two fixes, both required: (1) Stop bundling admin "
                    "JavaScript into the public bundle. Most modern build "
                    "tools (Webpack, Vite, Next.js) support route-based "
                    "splitting — the admin code should only load for admin "
                    "users. (2) Treat every endpoint as untrusted: every "
                    "admin route must enforce server-side authorisation on "
                    "every request, not just present-or-not in the UI. "
                    "Hiding the URL is not access control."
                ),
                framework=_FA["internal_api_in_client"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "internal_endpoints": internal[:20]},
            ))

        tokenized = by_tag.get("token_in_url", [])
        if tokenized:
            redacted: list[str] = []
            keys_seen: set[str] = set()
            for url in tokenized[:5]:
                m = _TOKEN_QS_RE.search(url)
                if not m:
                    continue
                keys_seen.add(m.group(1).lower())
                redacted.append(_TOKEN_QS_RE.sub(
                    lambda mm: f"{mm.group(0).split('=', 1)[0]}=<redacted>",
                    url,
                ))
            findings.append(Finding(
                title="API keys or tokens transmitted in URL query strings",
                description=(
                    f"At least {len(tokenized)} client-side request URL(s) "
                    "carry a secret-looking value in the query string "
                    f"(parameters: {', '.join(sorted(keys_seen))}). URLs are "
                    "logged by web servers, CDNs, reverse proxies, browser "
                    "history, and bookmarks — and they leak to third parties "
                    "via the Referer header. Treat any secret that has ever "
                    "been transmitted this way as compromised; rotate it "
                    "even if the leak is now fixed."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="Tokenised URLs (values redacted):\n" + "\n".join(redacted),
                    location=page_url,
                    source_engine=_ENGINE,
                    extra={"params_seen": sorted(keys_seen)},
                )],
                confidence=0.9,
                remediation=(
                    "Move the token out of the URL: use a request header "
                    "(`Authorization: Bearer …` for OAuth, `X-API-Key: …` for "
                    "static keys) or POST it in the request body. Scrub any "
                    "log retention systems for the values that were leaked. "
                    "Rotate the tokens — there's no way to claw them back "
                    "from the third parties they were referer-leaked to."
                ),
                framework=_FA["token_in_url"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "token_keys": sorted(keys_seen)},
            ))

        ws_insecure = by_tag.get("insecure_websocket", [])
        if ws_insecure and page_scheme == "https":
            findings.append(Finding(
                title="Insecure WebSocket (ws://) opened from an HTTPS page",
                description=(
                    "The page itself loaded over HTTPS but opens a WebSocket "
                    f"with the `ws://` scheme: {ws_insecure[0]}. WebSocket "
                    "frames over `ws://` are unencrypted — any data the "
                    "browser sends, including auth tokens shipped during the "
                    "handshake or in messages, is readable by anyone on the "
                    "network. Modern browsers usually block this as "
                    "'mixed content' but older browsers and some embedded "
                    "contexts may not."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="WebSocket URLs:\n" + "\n".join(ws_insecure[:5]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.95,
                remediation=(
                    "Change every `ws://` URL to `wss://` and serve the "
                    "WebSocket server with a TLS certificate. If the server "
                    "is behind a load balancer, terminate TLS at the LB and "
                    "speak plain WS internally on a private network."
                ),
                framework=_FA["insecure_websocket"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "ws_insecure": ws_insecure},
            ))

        api_spec = by_tag.get("api_spec", [])
        if api_spec:
            findings.append(Finding(
                title=f"API specification document referenced ({len(api_spec)})",
                description=(
                    "The page references an OpenAPI/Swagger/Redoc spec at "
                    f"{api_spec[0]}. An OpenAPI document is a complete map "
                    "of every endpoint, parameter, and response shape on "
                    "the API — extremely useful for developers and equally "
                    "useful for an attacker performing reconnaissance. Spec "
                    "documents are commonly left exposed because the "
                    "team's documentation tool (Swagger UI, Redoc, Stoplight) "
                    "expects to fetch them at a well-known URL."
                ),
                severity=Severity.LOW,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="Spec URLs:\n" + "\n".join(api_spec[:5]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.85,
                remediation=(
                    "If the spec is public-by-design (you're shipping a "
                    "developer API), leave it — make sure it accurately "
                    "documents which endpoints require auth. If it's "
                    "internal, gate the route behind authentication or "
                    "restrict it to your office IP range. Don't include "
                    "internal-only endpoints in the spec at all if it's "
                    "going to be public."
                ),
                framework=_FA["api_spec_exposed"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "spec_urls": api_spec},
            ))

        internal_infra = by_tag.get("internal_infra", [])
        if internal_infra:
            findings.append(Finding(
                title="Internal infrastructure hostname leaked in client JavaScript",
                description=(
                    "Client-side JavaScript contains hardcoded references to "
                    f"internal infrastructure: {internal_infra[0]}. Examples "
                    "include private IPs (10.x, 192.168.x), `.local` / "
                    "`.internal` hostnames, AWS ELB internal DNS, Azure "
                    "internal service URLs, or Google Cloud project IDs. "
                    "An attacker uses these to map the internal network "
                    "topology and to craft Server-Side Request Forgery "
                    "(SSRF) payloads when they find an upload or fetch "
                    "feature."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.API,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content="Internal hostnames:\n" + "\n".join(internal_infra[:10]),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.85,
                remediation=(
                    "Move environment-specific hostnames into a "
                    "build-time configuration that resolves to the public "
                    "FQDN in production. Add a CI check that fails the "
                    "build if any internal hostname pattern appears in "
                    "shipped bundles. Where SSRF protection is at the "
                    "infrastructure layer (network ACLs, IMDSv2, VPC "
                    "endpoint policies), verify those controls are "
                    "in place — they're the real defence."
                ),
                framework=_FA["internal_infra_leaked"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "internal_hosts": internal_infra},
            ))

        return findings
