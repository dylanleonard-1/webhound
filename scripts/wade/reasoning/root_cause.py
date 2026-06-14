"""Phase 8D: WADE Root Cause Reasoning.

Identifies likely root causes for findings and finding clusters.
Advisory only — does NOT modify production findings or severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import ConfidenceLevel, Finding, ReasoningEvidence


@dataclass
class RootCauseEvidence:
    indicator: str
    rationale: str
    sources: list[str] = field(default_factory=list)


@dataclass
class RootCauseSummary:
    root_cause: str
    category: str        # e.g. "deploy_misconfiguration", "email_security_gap"
    description: str
    remediation_hint: str
    affected_findings: list[str] = field(default_factory=list)


@dataclass
class RootCauseConfidence:
    level: ConfidenceLevel
    score: float
    rationale: str


@dataclass
class RootCauseResult:
    summary: RootCauseSummary
    confidence: RootCauseConfidence
    evidence: list[RootCauseEvidence]
    advisory_only: bool = True

    def summary_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.summary.root_cause,
            "category": self.summary.category,
            "description": self.summary.description,
            "remediation_hint": self.summary.remediation_hint,
            "confidence": self.confidence.level.value,
            "advisory_only": self.advisory_only,
        }


# ---------------------------------------------------------------------------
# Root cause patterns
# ---------------------------------------------------------------------------

_DEPLOY_MISCONFIGURATION = frozenset({
    "missing_csp", "missing_hsts", "missing_x_frame_options",
    "missing_secure_cookie", "missing_httponly_cookie", "missing_samesite_cookie",
})

_EMAIL_SECURITY_GAP = frozenset({"missing_dmarc", "missing_dkim", "missing_spf"})

_PROVIDER_BEHAVIOR = frozenset({
    "cloudflare_challenge_page", "vercel_deployment_protection", "provider_blocked_scan",
})

_RATE_LIMITING = frozenset({"provider_blocked_scan", "cloudflare_challenge_page"})

_SECRET_EXPOSURE = frozenset({"exposed_env", "exposed_git", "exposed_backup_file"})

_DEPRECATED_STACK = frozenset({"tls_misconfiguration", "tls_expiry", "wordpress_xmlrpc"})

_API_MISCONFIGURATION = frozenset({
    "graphql_exposure", "swagger_exposure", "api_exposure",
})


def _cause_deploy_misconfiguration(
    types: frozenset[str],
) -> RootCauseResult | None:
    matched = _DEPLOY_MISCONFIGURATION & types
    if len(matched) < 2:
        return None
    return RootCauseResult(
        summary=RootCauseSummary(
            root_cause="Deploy/CDN configuration missing security header defaults",
            category="deploy_misconfiguration",
            description=(
                f"{len(matched)} security headers are absent ({', '.join(sorted(matched))}). "
                "When multiple headers are missing together, the most common root cause is "
                "a CDN or reverse-proxy configuration that does not set security headers "
                "by default, and no application-level middleware is adding them. This is "
                "typically introduced during a CDN migration or infrastructure change."
            ),
            remediation_hint=(
                "Add security headers at the CDN/reverse-proxy layer (Cloudflare Transform Rules, "
                "Vercel headers config, nginx add_header) so all responses carry them. "
                "Audit the deployment that started the regression."
            ),
            affected_findings=list(matched),
        ),
        confidence=RootCauseConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.80,
            rationale="Multi-header absence is a classic CDN/proxy misconfiguration signature",
        ),
        evidence=[
            RootCauseEvidence(
                indicator=f"{len(matched)} security headers absent",
                rationale="Individual gaps may be mistakes; clusters indicate systematic config absence",
                sources=["OWASP Security Headers Project"],
            )
        ],
    )


def _cause_provider_behavior(types: frozenset[str]) -> RootCauseResult | None:
    matched = _PROVIDER_BEHAVIOR & types
    if not matched:
        return None
    return RootCauseResult(
        summary=RootCauseSummary(
            root_cause="Provider WAF/deployment protection masking scan coverage",
            category="provider_behavior",
            description=(
                "Findings such as Cloudflare challenge pages or Vercel deployment "
                "protection are provider security controls, not customer vulnerabilities. "
                "These reduce scan coverage — the scanner cannot see behind the WAF — "
                "but do not represent customer-introduced risk. Rate-limiting and "
                "challenge pages are expected behavior."
            ),
            remediation_hint=(
                "To improve scan coverage: add the scanner IP to WAF allowlist or "
                "configure a scanner-specific bypass header. "
                "Do NOT report challenge pages as customer vulnerabilities."
            ),
            affected_findings=list(matched),
        ),
        confidence=RootCauseConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.90,
            rationale="Provider-behavior findings have well-known root causes; not customer risk",
        ),
        evidence=[
            RootCauseEvidence(
                indicator="challenge page or deployment protection response",
                rationale="Provider WAF/CDN blocking scanner requests is expected security behavior",
                sources=["WADE provider knowledge corpus"],
            )
        ],
    )


def _cause_secret_exposure(types: frozenset[str]) -> RootCauseResult | None:
    matched = _SECRET_EXPOSURE & types
    if not matched:
        return None
    return RootCauseResult(
        summary=RootCauseSummary(
            root_cause="Sensitive files publicly accessible — likely deployment or gitignore misconfiguration",
            category="secret_exposure",
            description=(
                "Exposed .env, .git, or backup files indicate that deployment processes "
                "are copying sensitive files into the web root, or that gitignore/server "
                "access control rules are not excluding them. This is a critical root cause "
                "that typically requires immediate investigation."
            ),
            remediation_hint=(
                "Immediately remove/block access to the exposed files and rotate ALL credentials "
                "in exposed files. Audit deployment scripts and gitignore rules. "
                "Implement DENY rules for sensitive file extensions at the web server level."
            ),
            affected_findings=list(matched),
        ),
        confidence=RootCauseConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.95,
            rationale="Sensitive file exposure is directly verifiable; root cause is consistent",
        ),
        evidence=[
            RootCauseEvidence(
                indicator=f"Sensitive files exposed: {', '.join(sorted(matched))}",
                rationale="Direct HTTP access to sensitive files confirms web-root inclusion",
                sources=["CWE-538", "OWASP A02:2021"],
            )
        ],
    )


def _cause_deprecated_stack(types: frozenset[str]) -> RootCauseResult | None:
    matched = _DEPRECATED_STACK & types
    if not matched:
        return None
    return RootCauseResult(
        summary=RootCauseSummary(
            root_cause="Outdated/deprecated technology stack not updated",
            category="deprecated_stack",
            description=(
                "Deprecated TLS versions, expired certificates, or old CMS components "
                "indicate the technology stack has not been maintained. This commonly "
                "results from manual certificate management without renewal automation, "
                "or a CMS installation that has not received security updates."
            ),
            remediation_hint=(
                "Enable automatic certificate renewal (Let's Encrypt + certbot, "
                "or CDN-managed certificates). Update TLS configuration to TLS 1.2+ "
                "with modern cipher suites. Apply CMS security patches."
            ),
            affected_findings=list(matched),
        ),
        confidence=RootCauseConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.70,
            rationale="Deprecated stack pattern has multiple causes; manual vs automated cert differs",
        ),
        evidence=[
            RootCauseEvidence(
                indicator=f"Deprecated stack signals: {', '.join(sorted(matched))}",
                rationale="Expired certs + weak TLS cluster around maintenance gaps",
                sources=["CWE-295", "CWE-326"],
            )
        ],
    )


def _cause_api_misconfiguration(types: frozenset[str]) -> RootCauseResult | None:
    matched = _API_MISCONFIGURATION & types
    if not matched:
        return None
    return RootCauseResult(
        summary=RootCauseSummary(
            root_cause="API introspection/documentation left enabled in production",
            category="api_misconfiguration",
            description=(
                "Swagger/OpenAPI docs or GraphQL introspection endpoints are publicly "
                "accessible. These are typically enabled by default in development "
                "frameworks and not disabled before production deployment."
            ),
            remediation_hint=(
                "Disable GraphQL introspection in production configuration. "
                "Restrict Swagger/OpenAPI endpoints behind authentication or IP allowlist. "
                "Review framework defaults for API documentation visibility."
            ),
            affected_findings=list(matched),
        ),
        confidence=RootCauseConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.82,
            rationale="Framework-default-on API exposure is a well-documented misconfiguration pattern",
        ),
        evidence=[
            RootCauseEvidence(
                indicator=f"API exposure: {', '.join(sorted(matched))}",
                rationale="Framework defaults typically enable these; production hardening is the gap",
                sources=["OWASP API Security Top 10"],
            )
        ],
    )


_ROOT_CAUSE_RULES = (
    _cause_deploy_misconfiguration,
    _cause_provider_behavior,
    _cause_secret_exposure,
    _cause_deprecated_stack,
    _cause_api_misconfiguration,
)


class RootCauseReasoner:
    """Identifies root causes from a set of scan findings. Advisory only."""

    def analyse(self, findings: list[Finding]) -> list[RootCauseResult]:
        types = frozenset(f.finding_type for f in findings)
        results: list[RootCauseResult] = []
        for rule in _ROOT_CAUSE_RULES:
            try:
                result = rule(types)
                if result is not None:
                    results.append(result)
            except Exception:
                continue
        return results
