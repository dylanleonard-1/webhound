# WebHound — scanner/webhound/core/security_stories.py
# Phase-8 correlation engine: turns a pile of findings into a handful of
# customer-facing security STORIES.
#
# This sits ABOVE the existing threat-chain correlation
# (core/correlation.py, which bumps confidence + emits cluster findings).
# Where that engine answers "do these signals form a known compromise
# pattern?", this layer answers the broader product question:
#
#     "What are the 2-3 things a human analyst would actually tell the
#      customer about this site?"
#
# A story groups related findings (and WADE changes) under a standardized
# CorrelationType, explains WHY they matter together in plain language,
# and carries a confidence. Stories are an EXPLANATION layer: they
# reorganize existing findings, they do NOT create new scored findings,
# so correlating three findings into one story never inflates the risk
# score (Task 10 — no double counting).
#
# No network. Pure functions over grouped findings + WADE assessments.

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from webhound.core.trust_policy import (
    confidence_label_of,
    finding_type_of,
)
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Standardized taxonomy (Tasks 8 + 9)
# ---------------------------------------------------------------------------


class CorrelationType(str, Enum):
    ADMIN_EXPOSURE       = "admin_exposure"
    AUTH_SURFACE         = "auth_surface"
    PAYMENT_SURFACE      = "payment_surface"
    SUPPLY_CHAIN_RISK    = "supply_chain_risk"
    POSSIBLE_COMPROMISE  = "possible_compromise"
    SCRIPT_ANOMALY       = "script_anomaly"
    THIRD_PARTY_CHANGE   = "third_party_change"
    API_EXPOSURE         = "api_exposure"
    WEBSITE_MODIFICATION = "website_modification"
    HEADER_HARDENING     = "header_hardening"
    COOKIE_HARDENING     = "cookie_hardening"


class CorrelationConfidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HEURISTIC = "heuristic"

    @property
    def rank(self) -> int:
        return {"heuristic": 1, "low": 2, "medium": 3,
                "high": 4, "confirmed": 5}[self.value]


# Stories that are descriptive inventory unless a suspicious signal joins
# them — they should never read as alarms on their own (Tasks 7, 12).
INVENTORY_TYPES: frozenset[CorrelationType] = frozenset({
    CorrelationType.API_EXPOSURE,
    CorrelationType.PAYMENT_SURFACE,
    CorrelationType.THIRD_PARTY_CHANGE,
})

HARDENING_TYPES: frozenset[CorrelationType] = frozenset({
    CorrelationType.HEADER_HARDENING,
    CorrelationType.COOKIE_HARDENING,
})


# ---------------------------------------------------------------------------
# Story model
# ---------------------------------------------------------------------------


@dataclass
class SecurityStory:
    """One customer-facing security narrative built from related findings."""

    correlation_id: str
    correlation_type: CorrelationType
    confidence: CorrelationConfidence
    title: str
    narrative: str
    recommendation: str
    severity: Severity
    member_finding_ids: list[str] = field(default_factory=list)
    affected_areas: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    is_inventory: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "narrative": self.narrative,
            "recommendation": self.recommendation,
            "severity": self.severity.value,
            "member_finding_ids": list(self.member_finding_ids),
            "affected_areas": list(self.affected_areas),
            "signals": list(self.signals),
            "is_inventory": self.is_inventory,
        }


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _text(gf: Any) -> str:
    return (getattr(gf, "title", "") or "").lower()


def _engine(gf: Any) -> str:
    return getattr(gf, "scanner_engine", "") or ""


def _category(gf: Any) -> str:
    cat = getattr(gf, "category", None)
    return getattr(cat, "value", str(cat or ""))


def _meta(gf: Any) -> dict:
    return getattr(gf, "metadata", None) or {}


def _member_id(gf: Any) -> str:
    """Stable per-finding identity used both as the story's member id and
    as the annotation lookup key. Finding carries a real UUID; grouped
    findings don't, so fall back to a deterministic title+engine hash."""
    fid = getattr(gf, "id", None)
    if fid:
        return str(fid)
    basis = f"{_engine(gf)}|{getattr(gf, 'title', '')}|{_category(gf)}"
    return "gf_" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _kw(gf: Any, kws: Iterable[str]) -> bool:
    t = _text(gf)
    return any(k in t for k in kws)


def _areas(findings: list[Any]) -> list[str]:
    """Best-effort customer-facing 'affected areas' from member metadata /
    URLs. Falls back to affected_urls hosts."""
    out: list[str] = []
    seen: set[str] = set()
    for gf in findings:
        ctx = _meta(gf).get("page_context") or _meta(gf).get("context")
        candidates = []
        if ctx:
            candidates.append(str(ctx).replace("_", " ").title())
        for u in (getattr(gf, "affected_urls", None) or [])[:2]:
            candidates.append(u)
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out[:6]


def _id(corr_type: CorrelationType, members: list[Any]) -> str:
    """Stable correlation id from type + sorted member identities, so the
    same story keeps its id across scans (timeline-friendly)."""
    parts = sorted(
        f"{_engine(m)}|{getattr(m, 'title', '')}" for m in members
    )
    h = hashlib.sha256(
        (corr_type.value + "::" + "||".join(parts)).encode("utf-8")
    ).hexdigest()[:16]
    return f"corr_{corr_type.value}_{h}"


def _is_known_vendor_finding(gf: Any) -> bool:
    """A finding about a recognised vendor (Stripe/GA/Shopify/...) — used
    to suppress supply-chain false positives (Tasks 4, 12)."""
    md = _meta(gf)
    if md.get("vendor_category") and md.get("vendor_category") != "unknown":
        return True
    host = md.get("host") or md.get("domain")
    if host:
        try:
            from webhound.threat_intel.domain_classifier import (
                DomainClass, DomainClassifier,
            )
            cls = DomainClassifier().classify(str(host))
            return cls.classification in (
                DomainClass.TRUSTED, DomainClass.COMMON_BENIGN,
            )
        except Exception:  # noqa: BLE001
            return False
    return False


def _threat_hit(gf: Any) -> bool:
    md = _meta(gf)
    tags = {t.lower() for t in (getattr(gf, "tags", None) or [])}
    return bool(
        md.get("enrichment") or md.get("urlhaus") or md.get("virustotal")
        or "enrichment_confirmed" in tags
        or _kw(gf, ["malicious", "flagged by"])
    )


def _confidence_for(signal_count: int, *, threat_hit: bool,
                    confirmed_member: bool) -> CorrelationConfidence:
    """Task 9: confidence grows with converging evidence."""
    if threat_hit:
        return CorrelationConfidence.CONFIRMED
    if signal_count >= 3:
        return CorrelationConfidence.HIGH
    if signal_count == 2:
        return (CorrelationConfidence.HIGH if confirmed_member
                else CorrelationConfidence.MEDIUM)
    return CorrelationConfidence.LOW


def _max_severity(members: list[Any]) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    rank = {s: i for i, s in enumerate(order)}
    best = Severity.INFO
    for m in members:
        s = getattr(m, "severity", Severity.INFO)
        if rank.get(s, 0) > rank.get(best, 0):
            best = s
    return best


# ---------------------------------------------------------------------------
# Detectors. Each takes the grouped-finding list and returns a story or None.
# ---------------------------------------------------------------------------


def _first(findings: list[Any], pred) -> Any | None:
    return next((f for f in findings if pred(f)), None)


def _all(findings: list[Any], pred) -> list[Any]:
    return [f for f in findings if pred(f)]


def _is_admin_path_finding(f: Any) -> bool:
    if _engine(f) != "sensitive_paths":
        return False
    path = str(_meta(f).get("path", "")).lower()
    return (_kw(f, ["admin", "login", "phpmyadmin", "adminer"])
            or any(k in path for k in ("admin", "login")))


def _detect_admin_exposure(findings: list[Any]) -> SecurityStory | None:
    admin = _first(findings, _is_admin_path_finding)
    api = _first(findings, lambda f: _category(f) == "api"
                 and _kw(f, ["admin", "internal"]))
    weak_auth = _first(findings, lambda f: _category(f) == "security_header"
                       or _engine(f) in ("form_risk", "cookie_scanner"))
    members = [m for m in (admin, api, weak_auth) if m is not None]
    if admin is None or len(members) < 2:
        return None
    threat = any(_threat_hit(m) for m in members)
    conf = _confidence_for(len(members), threat_hit=threat,
                           confirmed_member=any(
                               confidence_label_of(m) == "confirmed"
                               for m in members))
    return SecurityStory(
        correlation_id=_id(CorrelationType.ADMIN_EXPOSURE, members),
        correlation_type=CorrelationType.ADMIN_EXPOSURE,
        confidence=conf,
        title="Administrative Exposure Surface",
        narrative=(
            "WebHound found an administrative or login surface reachable "
            "from the public internet, together with related signals "
            "(admin-style API references and/or weak authentication "
            "controls). On their own each is minor; together they map the "
            "surface an attacker would target first to gain privileged "
            "access. Reviewing them as one surface is more useful than "
            "chasing each finding separately."
        ),
        recommendation=(
            "Restrict the admin surface to a VPN or IP allowlist, enforce "
            "MFA on privileged logins, and confirm admin APIs require "
            "server-side authorization."
        ),
        severity=_max_severity(members),
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members],
    )


def _detect_auth_surface(findings: list[Any]) -> SecurityStory | None:
    login_form = _first(findings, lambda f: _engine(f) in (
        "form_risk", "input_analysis")
        and _kw(f, ["login", "password", "credential", "sign in", "auth"]))
    auth_api = _first(findings, lambda f: _category(f) == "api"
                      and _kw(f, ["auth", "session", "login", "token"]))
    weak_session = _first(findings, lambda f: _engine(f) == "cookie_scanner"
                          and _kw(f, ["httponly", "secure", "samesite",
                                      "session"]))
    members = [m for m in (login_form, auth_api, weak_session)
               if m is not None]
    if login_form is None or len(members) < 2:
        return None
    conf = _confidence_for(
        len(members), threat_hit=False,
        confirmed_member=any(confidence_label_of(m) == "confirmed"
                             for m in members))
    return SecurityStory(
        correlation_id=_id(CorrelationType.AUTH_SURFACE, members),
        correlation_type=CorrelationType.AUTH_SURFACE,
        confidence=conf,
        title="Authentication Surface Review",
        narrative=(
            "WebHound mapped your authentication surface: a login form, "
            "the auth/session API it talks to, and the session-cookie "
            "controls protecting it. This is the path every account "
            "takeover attempt follows, so it's worth reviewing as a "
            "single flow rather than three disconnected findings."
        ),
        recommendation=(
            "Ensure session cookies carry Secure + HttpOnly + SameSite, "
            "rate-limit and lock out the login endpoint, and require MFA "
            "for sensitive accounts."
        ),
        severity=_max_severity(members),
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members],
    )


def _detect_payment_surface(findings: list[Any]) -> SecurityStory | None:
    payment_form = _first(findings, lambda f: _engine(f) in (
        "form_risk", "input_analysis")
        and _kw(f, ["payment", "checkout", "card", "credit", "cvv", "pay"]))
    payment_vendor = _first(findings, lambda f:
                            _meta(f).get("vendor_category") == "payment"
                            or _kw(f, ["stripe", "paypal", "braintree",
                                       "klarna", "adyen", "square"]))
    members = [m for m in (payment_form, payment_vendor) if m is not None]
    if not members:
        return None
    suspicious = any(_threat_hit(m) for m in members) or any(
        finding_type_of(m) in ("confirmed_risk", "likely_risk",
                               "heuristic_signal")
        and _engine(m) in ("obfuscation_detector", "hidden_iframes",
                           "injected_js", "suspicious_redirects")
        for m in findings)
    # Suspicious payment context escalates; otherwise inventory only.
    if suspicious:
        conf = CorrelationConfidence.HIGH
        sev = Severity.HIGH
        is_inventory = False
        narrative = (
            "WebHound observed your payment surface (checkout / payment "
            "form and a payment provider) alongside a suspicious signal "
            "on the same flow. Payment pages are the prime target for "
            "skimming, so this combination warrants investigation."
        )
        rec = ("Investigate the suspicious signal on the payment flow "
               "immediately, verify your payment scripts against the "
               "provider's official versions, and enforce a strict CSP "
               "on checkout.")
    else:
        conf = CorrelationConfidence.MEDIUM
        sev = Severity.INFO
        is_inventory = True
        narrative = (
            "WebHound mapped your payment processing surface: the "
            "checkout/payment form and the third-party payment provider "
            "it uses. No suspicious indicators were found — this is "
            "recorded for visibility, not as a problem."
        )
        rec = ("Keep payment scripts pinned to the provider's official "
               "sources and review them after any vendor change.")
    return SecurityStory(
        correlation_id=_id(CorrelationType.PAYMENT_SURFACE, members),
        correlation_type=CorrelationType.PAYMENT_SURFACE,
        confidence=conf,
        title="Payment Processing Surface",
        narrative=narrative,
        recommendation=rec,
        severity=sev,
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members],
        is_inventory=is_inventory,
    )


def _detect_supply_chain(findings: list[Any]) -> SecurityStory | None:
    # New / external third-party script that is NOT a known vendor.
    unknown_script = _first(findings, lambda f:
                            _engine(f) in ("third_party_domains",
                                           "js_analyzer")
                            and not _is_known_vendor_finding(f)
                            and _kw(f, ["third-party", "third party",
                                        "external script", "unknown"]))
    threat = _first(findings, lambda f: _threat_hit(f)
                    and not _is_known_vendor_finding(f))
    members = [m for m in (unknown_script, threat) if m is not None]
    if len(members) < 2:
        return None
    conf = _confidence_for(len(members), threat_hit=threat is not None,
                           confirmed_member=True)
    return SecurityStory(
        correlation_id=_id(CorrelationType.SUPPLY_CHAIN_RISK, members),
        correlation_type=CorrelationType.SUPPLY_CHAIN_RISK,
        confidence=conf,
        title="Supply Chain Risk",
        narrative=(
            "WebHound found an unrecognised third-party script combined "
            "with a threat-intelligence indicator on the same vendor. "
            "Known providers (Google, Stripe, Cloudflare, Shopify, …) are "
            "excluded from this story — this is specifically about code "
            "you may not have vetted running inside your origin."
        ),
        recommendation=(
            "Identify the vendor behind the script, confirm you rely on "
            "it, and remove it if not. Pin trusted scripts with "
            "Subresource Integrity and tighten CSP to an explicit "
            "allowlist."
        ),
        severity=_max_severity(members),
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members],
    )


def _detect_possible_compromise(findings: list[Any]) -> SecurityStory | None:
    unknown_script = _first(findings, lambda f:
                            _engine(f) in ("injected_js", "obfuscation_detector",
                                           "js_analyzer")
                            and _kw(f, ["inject", "obfuscat", "unknown",
                                        "suspicious", "eval", "unexpected"]))
    iframe = _first(findings, lambda f: _engine(f) == "hidden_iframes"
                    or _kw(f, ["hidden iframe", "invisible iframe"]))
    redirect = _first(findings, lambda f: _engine(f) == "suspicious_redirects"
                      or _kw(f, ["suspicious redirect", "unexpected redirect"]))
    members = [m for m in (unknown_script, iframe, redirect)
               if m is not None]
    if len(members) < 2:
        return None
    threat = any(_threat_hit(m) for m in members)
    # Confidence grows as evidence grows (Task 3 + 9).
    conf = _confidence_for(len(members), threat_hit=threat,
                           confirmed_member=True)
    return SecurityStory(
        correlation_id=_id(CorrelationType.POSSIBLE_COMPROMISE, members),
        correlation_type=CorrelationType.POSSIBLE_COMPROMISE,
        confidence=conf,
        title="Possible Website Compromise",
        narrative=(
            "WebHound detected multiple related indicators that commonly "
            "appear together during website compromise — such as an "
            "unexpected script, a hidden iframe, and a suspicious "
            "redirect. Any one alone is often benign; seeing them "
            "together is the pattern worth investigating."
        ),
        recommendation=(
            "Investigate immediately. Snapshot the affected pages and "
            "scripts, compare against your known-good build, and review "
            "recent CMS / plugin / vendor changes."
        ),
        severity=_max_severity(members) if _max_severity(members).rank
        >= Severity.MEDIUM.rank else Severity.MEDIUM,
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members],
    )


def _detect_api_exposure(findings: list[Any]) -> SecurityStory | None:
    api_findings = _all(findings, lambda f: _category(f) == "api")
    if len(api_findings) < 1:
        return None
    # API exposure is inventory unless a member is itself a risk finding.
    risky = [m for m in api_findings
             if finding_type_of(m) in ("confirmed_risk", "likely_risk")]
    members = api_findings
    is_inventory = not risky
    return SecurityStory(
        correlation_id=_id(CorrelationType.API_EXPOSURE, members),
        correlation_type=CorrelationType.API_EXPOSURE,
        confidence=CorrelationConfidence.HIGH if not is_inventory
        else CorrelationConfidence.MEDIUM,
        title="API Surface",
        narrative=(
            "WebHound mapped the API endpoints your site references and "
            "calls. This is the backend surface an attacker would "
            "enumerate. " + (
                "One or more endpoints look risky and are worth review."
                if risky else
                "No risky endpoints stood out — recorded for visibility."
            )
        ),
        recommendation=(
            "Maintain an inventory of every API your frontend depends on, "
            "confirm each enforces authentication and rate limiting, and "
            "ensure error responses don't leak internals."
        ),
        severity=_max_severity(risky) if risky else Severity.INFO,
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members][:8],
        is_inventory=is_inventory,
    )


def _detect_header_hardening(findings: list[Any]) -> SecurityStory | None:
    members = _all(findings, lambda f: _category(f) == "security_header"
                   and finding_type_of(f) == "hardening")
    if len(members) < 2:
        return None
    return SecurityStory(
        correlation_id=_id(CorrelationType.HEADER_HARDENING, members),
        correlation_type=CorrelationType.HEADER_HARDENING,
        confidence=CorrelationConfidence.CONFIRMED,
        title="Browser Security Headers Need Improvement",
        narrative=(
            f"WebHound found {len(members)} browser-security-header "
            "improvements that strengthen defense-in-depth. These are "
            "hardening recommendations, not active vulnerabilities — "
            "grouped here so you can address them as one task."
        ),
        recommendation=(
            "Add the missing headers (CSP, Permissions-Policy, COOP/COEP, "
            "etc.) as part of a single hardening pass on your edge / web "
            "server configuration."
        ),
        severity=_max_severity(members),
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members][:10],
        is_inventory=False,
    )


def _detect_cookie_hardening(findings: list[Any]) -> SecurityStory | None:
    members = _all(findings, lambda f: _category(f) == "cookie"
                   and finding_type_of(f) in ("hardening", "likely_risk"))
    if len(members) < 2:
        return None
    return SecurityStory(
        correlation_id=_id(CorrelationType.COOKIE_HARDENING, members),
        correlation_type=CorrelationType.COOKIE_HARDENING,
        confidence=CorrelationConfidence.CONFIRMED,
        title="Cookie Security Improvements",
        narrative=(
            f"WebHound found {len(members)} cookie-security improvements "
            "(missing Secure / HttpOnly / SameSite flags). Grouped so you "
            "can fix them together; sensitive session cookies should be "
            "prioritized."
        ),
        recommendation=(
            "Set Secure + HttpOnly + SameSite on session/auth cookies "
            "first, then on the rest. Non-sensitive cookies are lower "
            "priority."
        ),
        severity=_max_severity(members),
        member_finding_ids=[_member_id(m) for m in members],
        affected_areas=_areas(members),
        signals=[getattr(m, "title", "") for m in members][:10],
        is_inventory=False,
    )


# Ordered most-severe / most-specific first. When a finding is claimed by
# an earlier story it can still join a later one (a finding may belong to
# multiple correlations — Task 1), but the *primary* correlation written
# onto the finding is the first (highest-priority) story it joined.
_DETECTORS = (
    _detect_possible_compromise,
    _detect_supply_chain,
    _detect_admin_exposure,
    _detect_payment_surface,
    _detect_auth_surface,
    _detect_api_exposure,
    _detect_header_hardening,
    _detect_cookie_hardening,
)


# ---------------------------------------------------------------------------
# WADE change correlation (Task 5)
# ---------------------------------------------------------------------------


def correlate_wade_changes(
    wade_timeline: dict | None,
) -> SecurityStory | None:
    """Build a WEBSITE_MODIFICATION story from this scan's WADE changes.

    Suppresses noise (Task 12): expected deployments / normal content
    updates and pure vendor additions don't constitute a 'modification'
    story. A modification story fires when ≥2 distinct change classes
    (new script / new domain / new form / iframe / redirect) co-occur."""
    if not wade_timeline:
        return None
    records = wade_timeline.get("records") or []
    if not records:
        return None

    SUSPICIOUS = {
        "suspicious_script_change", "suspicious_iframe",
        "suspicious_redirect", "possible_compromise",
        "confirmed_malicious_indicator",
    }
    NOISE = {"expected_deployment", "normal_content_update"}

    meaningful = [r for r in records
                  if r.get("change_type") not in NOISE]
    if len(meaningful) < 2:
        return None

    change_classes = {r.get("diff_type") for r in meaningful}
    has_suspicious = any(r.get("change_type") in SUSPICIOUS
                         for r in meaningful)
    if len(change_classes) < 2 and not has_suspicious:
        return None

    if has_suspicious:
        conf = CorrelationConfidence.HIGH
        sev = Severity.HIGH
        narrative = (
            "WebHound detected several website changes since the last "
            "scan that, together, match a potential-compromise pattern "
            "rather than a routine deployment."
        )
        rec = "Investigate the changes below before dismissing them."
    else:
        conf = CorrelationConfidence.MEDIUM
        sev = Severity.LOW
        narrative = (
            "WebHound detected multiple coordinated changes since the "
            "last scan (new scripts, domains, or forms). This usually "
            "indicates a deployment or a new tool rollout — review to "
            "confirm it was expected."
        )
        rec = "Confirm these changes correspond to a planned deployment."

    areas = []
    seen = set()
    for r in meaningful:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            areas.append(u)
    return SecurityStory(
        correlation_id="corr_website_modification_" + hashlib.sha256(
            "||".join(sorted(r.get("change_key", "") for r in meaningful)
                      ).encode()).hexdigest()[:16],
        correlation_type=CorrelationType.WEBSITE_MODIFICATION,
        confidence=conf,
        title="Unexpected Website Modification" if has_suspicious
        else "Website Modification Detected",
        narrative=narrative,
        recommendation=rec,
        severity=sev,
        member_finding_ids=[],
        affected_areas=areas[:6],
        signals=[f"{r.get('diff_type')}: {r.get('value') or r.get('url')}"
                 for r in meaningful][:10],
        is_inventory=not has_suspicious,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_security_stories(
    grouped_findings: list[Any],
    *,
    wade_timeline: dict | None = None,
) -> list[SecurityStory]:
    """Detect every applicable security story and annotate the member
    grouped findings in-place with their primary correlation.

    Stories are an explanation layer — they create NO scored findings,
    so they never inflate the risk score (Task 10)."""
    stories: list[SecurityStory] = []

    for detector in _DETECTORS:
        try:
            story = detector(grouped_findings)
        except Exception:  # noqa: BLE001
            continue
        if story is not None and story.member_finding_ids:
            stories.append(story)

    try:
        wade_story = correlate_wade_changes(wade_timeline)
        if wade_story is not None:
            stories.append(wade_story)
    except Exception:  # noqa: BLE001
        pass

    # Annotate members. A finding can belong to several stories; the first
    # (highest-priority) becomes its primary correlation_* fields, the full
    # set is recorded in metadata.correlation_ids.
    by_id = {_member_id(gf): gf for gf in grouped_findings}
    for story in stories:
        for fid in story.member_finding_ids:
            gf = by_id.get(fid)
            if gf is None:
                continue
            md = dict(getattr(gf, "metadata", None) or {})
            ids = set(md.get("correlation_ids") or [])
            ids.add(story.correlation_id)
            md["correlation_ids"] = sorted(ids)
            gf.metadata = md
            if getattr(gf, "correlation_id", None) is None:
                gf.correlation_id = story.correlation_id
                gf.correlation_type = story.correlation_type.value
                gf.correlation_confidence = story.confidence.value

    # Order: highest confidence + severity first (the customer reads these
    # top-down as "the 2-3 things that matter").
    sev_rank = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                Severity.LOW: 1, Severity.INFO: 0}
    stories.sort(
        key=lambda s: (s.confidence.rank, sev_rank.get(s.severity, 0)),
        reverse=True,
    )
    return stories
