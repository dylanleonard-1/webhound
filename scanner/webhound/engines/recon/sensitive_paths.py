# WebHound — scanner/webhound/engines/recon/sensitive_paths.py
# Active probing for commonly exposed sensitive paths.
#
# Safe-mode: HEAD + GET only. Respects scope and rate limits.
# Masks secrets in evidence. No brute force, no exploitation.

from __future__ import annotations

import re
from dataclasses import dataclass

from webhound.core.http_client import HttpResponse, SafeHttpClient
from webhound.core.scope import ScopeChecker
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity
from webhound.models.target import Target

_ENGINE = "sensitive_paths"


@dataclass(frozen=True)
class _PathDef:
    path: str
    label: str
    severity: Severity
    indicators: tuple[str, ...]  # body strings that confirm exposure; empty = status-only


_PATHS: list[_PathDef] = [
    _PathDef("/.env",          "Environment variable file",  Severity.CRITICAL, ("=", "PASSWORD", "SECRET", "KEY", "TOKEN", "DB_", "APP_")),
    _PathDef("/.git/config",   "Git repository config",      Severity.CRITICAL, ("[core]", "repositoryformatversion", "bare =")),
    _PathDef("/.git/",         "Git repository listing",     Severity.CRITICAL, ("HEAD", "config", "objects", "COMMIT")),
    _PathDef("/wp-config.php", "WordPress config file",      Severity.CRITICAL, ("DB_PASSWORD", "DB_HOST", "table_prefix", "<?php")),
    _PathDef("/config.php",    "PHP application config",     Severity.CRITICAL, ("<?php", "define(", "password", "database")),
    _PathDef("/phpinfo.php",   "PHP info disclosure",        Severity.MEDIUM,   ("phpinfo()", "PHP Version", "<title>phpinfo")),
    _PathDef("/backup.zip",    "Backup archive",             Severity.HIGH,     ()),
    _PathDef("/backup.sql",    "SQL database backup",        Severity.HIGH,     ("CREATE TABLE", "INSERT INTO", "-- MySQL", "DUMP")),
    _PathDef("/database.sql",  "SQL database dump",          Severity.HIGH,     ("CREATE TABLE", "INSERT INTO", "-- MySQL", "DUMP")),
    _PathDef("/db.sql",        "SQL database dump",          Severity.HIGH,     ("CREATE TABLE", "INSERT INTO", "-- MySQL", "DUMP")),
    _PathDef("/admin",         "Admin panel",                Severity.MEDIUM,   ()),
    _PathDef("/login",         "Login page",                 Severity.LOW,      ()),
    _PathDef("/debug",         "Debug endpoint",             Severity.MEDIUM,   ()),
    _PathDef("/staging",       "Staging environment",        Severity.MEDIUM,   ()),
    _PathDef("/test",          "Test endpoint",              Severity.LOW,      ()),
    _PathDef("/old",           "Legacy content",             Severity.LOW,      ()),
    _PathDef("/backup",        "Backup directory",           Severity.MEDIUM,   ()),
    _PathDef("/uploads",       "Uploads directory",          Severity.MEDIUM,   ()),
]

_BINARY_CONTENT_TYPES: frozenset[str] = frozenset({
    "application/zip", "application/x-zip-compressed",
    "application/octet-stream", "application/x-tar",
    "application/gzip", "application/x-gzip",
    "application/x-bzip2", "application/x-rar-compressed",
})

_ENV_VAR_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.+)$", re.M)
_INI_SECRET_RE = re.compile(
    r"^(\s*(?:password|passwd|secret|token|api_?key|auth|url)\s*[=:]\s*)(.+)$",
    re.M | re.I,
)
_PHP_DEFINE_RE = re.compile(
    r"(define\s*\(\s*['\"]"
    r"[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|SALT|AUTH|NONCE)[A-Z_]*"
    r"['\"]\s*,\s*)"
    r"(['\"][^'\"]*['\"])",
    re.I,
)

_DESCRIPTIONS: dict[str, str] = {
    "/.env": (
        "The .env environment file is publicly accessible. This file typically contains "
        "database credentials, API keys, secret tokens, and encryption keys. Its exposure "
        "represents a complete credential compromise and requires immediate remediation."
    ),
    "/.git/config": (
        "The .git/config file is publicly accessible. Git configuration files may reveal "
        "repository remote URLs (including private repositories), contributor emails, and "
        "branch structures. Attackers can use this to reconstruct partial or full source code."
    ),
    "/.git/": (
        "The .git/ directory is accessible from the web. This may allow reconstruction of "
        "the full source code, history, and secrets committed to the repository."
    ),
    "/wp-config.php": (
        "The WordPress configuration file is publicly accessible. This file contains database "
        "credentials (DB_PASSWORD, DB_HOST), secret keys, and salts. Its exposure allows "
        "direct database access and authentication bypass."
    ),
    "/config.php": (
        "A PHP configuration file is publicly accessible. This file likely contains database "
        "credentials or other sensitive application configuration that should never be "
        "reachable from the web."
    ),
    "/phpinfo.php": (
        "A phpinfo() page is publicly accessible. This page discloses the PHP version, "
        "server paths, enabled extensions, and configuration settings that aid attacker "
        "reconnaissance and exploit targeting."
    ),
}

_REMEDIATIONS: dict[str, str] = {
    "/.env": (
        "Move .env outside the web root or block access in your web server configuration. "
        "In nginx: deny access to dot-files. In Apache: use <FilesMatch '^\\.'> with Deny from all. "
        "Rotate all credentials exposed in the file immediately."
    ),
    "/.git/config": (
        "Block access to the .git/ directory in your web server configuration. "
        "In nginx: location ~* /\\.git { deny all; } "
        "In Apache: RedirectMatch 404 /\\.git. Rotate any secrets in commit history."
    ),
    "/.git/": (
        "Block web access to the .git/ directory. Remove it from the deployment artifact. "
        "Consider rotating any secrets that may have been committed to the repository."
    ),
    "/wp-config.php": (
        "Move wp-config.php one directory above the web root, or restrict access via "
        "web server rules. Rotate all database credentials and secret keys immediately."
    ),
    "/config.php": (
        "Move config.php outside the web root or deny web access to it. "
        "Rotate any credentials the file contains."
    ),
    "/phpinfo.php": (
        "Delete phpinfo.php from the production server. It serves no legitimate purpose "
        "in production. Disable expose_php in php.ini to reduce version disclosure."
    ),
}

_CWE_MAP: dict[str, list[str]] = {
    "config":  ["CWE-538", "CWE-200"],
    "scm":     ["CWE-527", "CWE-200"],
    "backup":  ["CWE-530", "CWE-200"],
    "admin":   ["CWE-284", "CWE-200"],
    "debug":   ["CWE-200"],
}


def _mask_secrets(text: str) -> str:
    text = _ENV_VAR_RE.sub(lambda m: f"{m.group(1)}=***", text)
    text = _INI_SECRET_RE.sub(lambda m: m.group(1) + "***", text)
    text = _PHP_DEFINE_RE.sub(lambda m: m.group(1) + "'***'", text)
    return text


def _safe_snippet(body: str, max_chars: int = 400) -> str:
    masked = _mask_secrets(body[: max_chars * 3])
    return masked[:max_chars].replace("\x00", "").replace("\r", "")


def _is_binary_response(response: HttpResponse) -> bool:
    ct = (response.content_type or "").lower().split(";")[0].strip()
    return ct in _BINARY_CONTENT_TYPES


def _body_confirms_exposure(body: str, spec: _PathDef) -> bool:
    if not spec.indicators or spec.severity == Severity.CRITICAL:
        return True
    body_str = body[:4096]
    return any(ind.upper() in body_str.upper() or ind in body_str for ind in spec.indicators)


def _confidence(body: str, spec: _PathDef) -> float:
    if not spec.indicators:
        return 0.75
    body_str = body[:4096]
    if any(ind.upper() in body_str.upper() or ind in body_str for ind in spec.indicators):
        return 0.92
    if spec.severity == Severity.CRITICAL:
        return 0.70
    return 0.60


def _description(spec: _PathDef) -> str:
    return _DESCRIPTIONS.get(spec.path, (
        f"The {spec.label.lower()} at '{spec.path}' is publicly accessible. "
        "This may expose sensitive information or functionality that should not be "
        "reachable from the public internet."
    ))


def _remediation(spec: _PathDef) -> str:
    return _REMEDIATIONS.get(spec.path, (
        f"Remove or restrict access to '{spec.path}' at the web server level. "
        "Sensitive files and directories should never be reachable from the public internet."
    ))


def _cwe_ids(spec: _PathDef) -> list[str]:
    if spec.path in ("/.env", "/wp-config.php", "/config.php"):
        return _CWE_MAP["config"]
    if "git" in spec.path:
        return _CWE_MAP["scm"]
    if spec.path in ("/backup.zip", "/backup.sql", "/database.sql", "/db.sql"):
        return _CWE_MAP["backup"]
    if spec.path in ("/admin", "/login", "/staging", "/debug", "/backup"):
        return _CWE_MAP["admin"]
    return _CWE_MAP["debug"]


class SensitivePathsEngine:
    """Active probing for commonly exposed sensitive paths.

    Sends HEAD (then GET when needed) requests to a fixed list of well-known
    sensitive paths relative to the target's base URL. Scope is respected and
    all secrets in response bodies are masked before being stored in evidence.

    Exposure is classified by:
    - HTTP status code (200 = exposed, 403/401 = access-controlled)
    - Response body indicators (KEY=VALUE in .env, [core] in .git/config, etc.)
    - Content-Type for binary archives (confirmed by content-type alone)

    Call ``await probe(target, client)`` to receive a list of findings.
    """

    NAME = _ENGINE

    async def probe(
        self,
        target: Target,
        client: SafeHttpClient,
        scope: ScopeChecker | None = None,
    ) -> list[Finding]:
        _scope = scope if scope is not None else ScopeChecker(target)
        findings: list[Finding] = []

        for spec in _PATHS:
            url = f"{target.base_url}{spec.path}"

            if not _scope.is_in_scope(url):
                continue

            head = await client.head(url)

            if head.failed or head.status_code == 404:
                continue

            if head.status_code == 200:
                # Binary files: skip GET, report on status + content-type alone.
                if _is_binary_response(head) and not spec.indicators:
                    findings.append(self._make_finding(spec, url, head, body="", request_method="HEAD"))
                    continue

                get = await client.get(url)
                if get.failed or get.status_code != 200:
                    continue

                if _body_confirms_exposure(get.body, spec):
                    findings.append(self._make_finding(spec, url, get, body=get.body))

            elif head.status_code in (401, 403) and spec.severity >= Severity.HIGH:
                findings.append(self._make_access_controlled_finding(spec, url, head))

        return findings

    def _make_finding(
        self,
        spec: _PathDef,
        url: str,
        response: HttpResponse,
        body: str,
        request_method: str = "GET",
    ) -> Finding:
        snippet = _safe_snippet(body) if body else ""
        evidence_content = (
            f"HTTP {response.status_code} {url}\n"
            f"Content-Type: {response.content_type or 'unknown'}"
            + (f"\n{snippet}" if snippet else "")
        )
        return Finding(
            title=f"Exposed {spec.label} detected",
            description=_description(spec),
            severity=spec.severity,
            category=FindingCategory.RECON,
            evidence=[Evidence(
                evidence_type=EvidenceType.HTTP_RESPONSE,
                content=evidence_content.strip(),
                location=url,
                source_engine=_ENGINE,
                request_method=request_method,
                status_code=response.status_code,
                extra={"path": spec.path, "content_type": response.content_type},
            )],
            confidence=_confidence(body, spec),
            remediation=_remediation(spec),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=_cwe_ids(spec),
                nist_controls=["CM-6", "CM-7"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": url, "path": spec.path, "status_code": response.status_code},
        )

    def _make_access_controlled_finding(
        self,
        spec: _PathDef,
        url: str,
        response: HttpResponse,
    ) -> Finding:
        return Finding(
            title=f"Access-controlled {spec.label} path exists",
            description=(
                f"The path '{spec.path}' returned HTTP {response.status_code}, indicating "
                f"the {spec.label.lower()} exists but is protected by access controls. "
                "While direct access is restricted, its existence confirms the presence "
                "of a sensitive resource and remains a target for authentication bypass."
            ),
            severity=Severity.LOW,
            category=FindingCategory.RECON,
            evidence=[Evidence(
                evidence_type=EvidenceType.HTTP_RESPONSE,
                content=f"HTTP {response.status_code} {url}",
                location=url,
                source_engine=_ENGINE,
                request_method="HEAD",
                status_code=response.status_code,
                extra={"path": spec.path},
            )],
            confidence=0.85,
            remediation=(
                f"Consider removing '{spec.path}' entirely rather than relying on access "
                "controls alone. A file that should not exist should not exist — not be hidden."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-200"],
                nist_controls=["CM-6"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": url, "path": spec.path, "status_code": response.status_code},
        )
