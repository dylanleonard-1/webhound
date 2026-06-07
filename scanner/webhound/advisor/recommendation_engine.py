# WebHound — scanner/webhound/advisor/recommendation_engine.py
# Phase-15 Task 8: turn the action plan into a customer-specific,
# de-duplicated, ordered remediation ROADMAP — the numbered path a
# customer follows ("Step 1: restrict admin access; Step 2: improve
# headers; Step 3: review vendors").
#
# Recommendations are consolidated by theme so a site with 8 missing
# headers becomes ONE roadmap step, not eight.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.advisor.action_plan import ActionBucket, build_action_plan
from webhound.core.trust_policy import finding_type_of

# Theme → (roadmap title, recommendation). A finding maps to a theme by
# engine/category so multiple findings collapse into one step.
_THEMES: dict[str, tuple[str, str]] = {
    "secrets": (
        "Remove exposed secrets and rotate credentials",
        "Take exposed config/secret files off the web root and rotate every "
        "credential they contained — assume they are compromised."),
    "admin_access": (
        "Restrict administrative access",
        "Put admin/login interfaces behind a VPN or IP allowlist, require "
        "MFA, and rate-limit the login form."),
    "compromise": (
        "Investigate possible tampering",
        "Compare affected pages to your known-good build, review recent "
        "CMS/plugin/vendor changes, and snapshot evidence."),
    "payment_forms": (
        "Secure payment and credential forms",
        "Ensure sensitive forms submit over HTTPS to your own origin and "
        "verify no unexpected script altered them."),
    "third_party": (
        "Review third-party vendors and scripts",
        "Confirm every external script is an intended vendor, pin trusted "
        "ones with Subresource Integrity, and tighten CSP to an allowlist."),
    "cookies": (
        "Harden cookie security",
        "Set Secure + HttpOnly + SameSite on session/auth cookies first."),
    "headers": (
        "Improve browser security headers",
        "Add the missing security headers (CSP, Permissions-Policy, "
        "COOP/COEP, etc.) at your edge in one hardening pass."),
    "api": (
        "Review exposed API endpoints",
        "Confirm each endpoint enforces authentication and rate limiting "
        "server-side and doesn't leak internal details."),
}

# Ordering of themes in the roadmap (most urgent first).
_THEME_ORDER = ("secrets", "compromise", "admin_access", "payment_forms",
                "third_party", "cookies", "api", "headers")


def _theme_of(f: Any) -> str | None:
    eng = getattr(f, "scanner_engine", "") or ""
    cat = getattr(getattr(f, "category", None), "value", "")
    title = (getattr(f, "title", "") or "").lower()
    ftype = finding_type_of(f)
    if ftype == "inventory":
        return None
    if eng == "sensitive_paths" and any(
            k in title for k in (".env", "environment variable", "secret",
                                 "credential", "config", "private key", "aws")):
        return "secrets"
    if eng == "secret_scanner":
        return "secrets"
    if eng == "sensitive_paths" and ("admin" in title or "login" in title):
        return "admin_access"
    if cat == "compromise" or eng in ("injected_js", "hidden_iframes",
                                      "suspicious_redirects",
                                      "obfuscation_detector"):
        return "compromise"
    if eng in ("form_risk", "input_analysis") and any(
            k in title for k in ("password", "payment", "credential",
                                 "checkout", "card")):
        return "payment_forms"
    if eng in ("threat_intel", "third_party_domains"):
        return "third_party"
    if cat == "cookie" or eng == "cookie_scanner":
        return "cookies"
    if cat == "security_header" or eng in ("security_headers", "csp_engine",
                                           "cors"):
        return "headers"
    if cat == "api" or eng == "endpoint_discovery":
        return "api"
    return None


@dataclass
class RoadmapStep:
    step: int
    title: str
    recommendation: str
    finding_count: int
    bucket: str               # the most-urgent bucket among its findings
    example_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "title": self.title,
            "recommendation": self.recommendation,
            "finding_count": self.finding_count,
            "priority": self.bucket,
            "example_findings": list(self.example_findings),
        }


def build_remediation_roadmap(grouped_findings: list[Any]) -> list[RoadmapStep]:
    """Consolidate findings into an ordered, de-duplicated roadmap."""
    plan = build_action_plan(grouped_findings)
    bucket_by_title = {i.title: i.bucket for i in plan.items}

    # Group findings by theme.
    by_theme: dict[str, list[Any]] = {}
    for f in grouped_findings:
        theme = _theme_of(f)
        if theme is None:
            continue
        by_theme.setdefault(theme, []).append(f)

    steps: list[RoadmapStep] = []
    for theme in _THEME_ORDER:
        findings = by_theme.get(theme)
        if not findings:
            continue
        title, rec = _THEMES[theme]
        # Most-urgent bucket among this theme's findings.
        buckets = [bucket_by_title.get(getattr(f, "title", ""),
                                       ActionBucket.MONITOR)
                   for f in findings]
        most_urgent = min(buckets, key=lambda b: b.order)
        steps.append(RoadmapStep(
            step=0,  # assigned below
            title=title, recommendation=rec,
            finding_count=len(findings),
            bucket=most_urgent.value,
            example_findings=[getattr(f, "title", "") for f in findings[:3]]))

    # Number the steps after ordering.
    for i, s in enumerate(steps, 1):
        s.step = i
    return steps
