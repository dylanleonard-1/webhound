# WebHound — scanner/webhound/advisor/risk_explainer.py
# Phase-15 WADE Security Advisor, Task 1: turn a finding into a four-part
# plain-language explanation — what happened, why it matters, what could
# happen, what to do. This is the heart of "translate scanner
# intelligence into guidance".
#
# Explanations are template-driven, keyed by engine/category with a
# finding_type fallback, so every finding gets an accurate, consistent,
# non-alarming explanation. Pure — duck-typed over Finding/GroupedFinding.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webhound.core.trust_policy import finding_type_of


@dataclass
class RiskExplanation:
    what_happened: str
    why_it_matters: str
    what_could_happen: str
    what_should_be_done: str
    confidence_label: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "what_happened": self.what_happened,
            "why_it_matters": self.why_it_matters,
            "what_could_happen": self.what_could_happen,
            "what_should_be_done": self.what_should_be_done,
            "confidence": self.confidence_label,
        }


def _engine(f: Any) -> str:
    return getattr(f, "scanner_engine", "") or ""


def _category(f: Any) -> str:
    c = getattr(f, "category", None)
    return getattr(c, "value", str(c or ""))


def _title(f: Any) -> str:
    return getattr(f, "title", "") or ""


def _conf(f: Any) -> str:
    md = getattr(f, "metadata", None) or {}
    return md.get("confidence_label", "medium")


def _kw(f: Any, *words: str) -> bool:
    t = _title(f).lower()
    return any(w in t for w in words)


# ---------------------------------------------------------------------------
# Engine/category-specific explanation builders. Each returns a
# RiskExplanation; the dispatcher picks the most specific match.
# ---------------------------------------------------------------------------


def _explain_sensitive_path(f: Any) -> RiskExplanation:
    if _kw(f, "environment variable", ".env", "credential", "secret",
           "config", "wp-config", "private key", "aws"):
        return RiskExplanation(
            what_happened=(
                "WebHound found a sensitive configuration or credential "
                f"file reachable from the internet ({_title(f)})."),
            why_it_matters=(
                "These files routinely contain database passwords, API "
                "keys, and secret tokens. Anyone who can load the URL can "
                "read them — no exploit required."),
            what_could_happen=(
                "An attacker could use the exposed credentials to access "
                "your database, cloud accounts, or third-party services "
                "directly."),
            what_should_be_done=(
                "Remove the file from the web root immediately, then "
                "ROTATE every credential it contained — assume they are "
                "already compromised. Block dotfiles / config paths at "
                "the web server."),
            confidence_label=_conf(f))
    if _kw(f, "admin", "login", "phpmyadmin", "adminer"):
        return RiskExplanation(
            what_happened=(
                "WebHound discovered an administrative or login interface "
                "accessible from the internet."),
            why_it_matters=(
                "Administrative interfaces are among the most frequently "
                "targeted entry points — they're where attackers focus "
                "credential-guessing and brute-force attempts."),
            what_could_happen=(
                "If credentials are weak, reused, or unprotected by MFA, "
                "an attacker could gain administrative control of the "
                "site."),
            what_should_be_done=(
                "Restrict access with a VPN or IP allowlist, require "
                "multi-factor authentication, and add rate-limiting and "
                "lockouts to the login form."),
            confidence_label=_conf(f))
    return _generic(f)


def _explain_cookie(f: Any) -> RiskExplanation:
    sess = _kw(f, "session", "auth")
    return RiskExplanation(
        what_happened=f"A cookie is missing a security attribute ({_title(f)}).",
        why_it_matters=(
            "Session and authentication cookies without Secure / HttpOnly "
            "/ SameSite can be stolen over insecure connections or by "
            "malicious scripts, and reused to impersonate a logged-in user."
            if sess else
            "Cookie security flags are a defense-in-depth control that "
            "limits how cookies can be accessed or sent."),
        what_could_happen=(
            "An attacker who captures the cookie could hijack the user's "
            "session and act as them."
            if sess else
            "On its own the impact is limited, but it weakens the overall "
            "protection of the cookie."),
        what_should_be_done=(
            "Set Secure + HttpOnly + SameSite on session/auth cookies as a "
            "priority; apply the same flags to other cookies as hardening."),
        confidence_label=_conf(f))


def _explain_headers(f: Any) -> RiskExplanation:
    return RiskExplanation(
        what_happened=(
            f"A browser security header is missing or weak ({_title(f)})."),
        why_it_matters=(
            "Security headers tell the browser how to protect your users "
            "— blocking clickjacking, script injection, and mixed content. "
            "This is hardening, not an active vulnerability."),
        what_could_happen=(
            "Without these headers, a separate flaw (like an injected "
            "script) would have fewer guardrails to stop it."),
        what_should_be_done=(
            "Add the missing header(s) at your web server or CDN edge as "
            "part of a single hardening pass."),
        confidence_label=_conf(f))


def _explain_form(f: Any) -> RiskExplanation:
    if _kw(f, "password", "credential", "insecure http", "different domain",
           "plain http"):
        return RiskExplanation(
            what_happened=(
                f"A form that handles sensitive input has a risky "
                f"configuration ({_title(f)})."),
            why_it_matters=(
                "Forms that send passwords or payment data over plain HTTP "
                "— or to a different domain — expose that data in transit "
                "or to an unexpected third party."),
            what_could_happen=(
                "Credentials or payment details could be intercepted or "
                "sent to an attacker-controlled destination (form-jacking)."),
            what_should_be_done=(
                "Ensure the form submits over HTTPS to your own origin, "
                "verify the action URL is correct, and confirm no "
                "unexpected script altered it."),
            confidence_label=_conf(f))
    return _generic(f)


def _explain_threat_intel(f: Any) -> RiskExplanation:
    return RiskExplanation(
        what_happened=(
            f"A third-party host on your site was flagged ({_title(f)})."),
        why_it_matters=(
            "The host is either on a threat-intelligence feed, impersonates "
            "a known brand, or shows strong abuse signals — meaning code "
            "from it may be running inside your site."),
        what_could_happen=(
            "If the host is malicious, any script it serves could steal "
            "data from your pages or redirect your visitors."),
        what_should_be_done=(
            "Confirm whether you intentionally use this host. If not, "
            "remove it and treat the page as potentially compromised — "
            "snapshot it and review recent changes."),
        confidence_label=_conf(f))


def _explain_compromise(f: Any) -> RiskExplanation:
    return RiskExplanation(
        what_happened=(
            f"WebHound observed an indicator associated with website "
            f"tampering ({_title(f)})."),
        why_it_matters=(
            "Hidden iframes, injected scripts, and unexpected redirects "
            "are classic signs that a site's code has been modified by "
            "someone other than its owner."),
        what_could_happen=(
            "If this is a real compromise, attackers may be skimming data, "
            "redirecting visitors, or serving malware to your users."),
        what_should_be_done=(
            "Investigate promptly: compare the page against your known-"
            "good build, review recent CMS/plugin/vendor changes, and "
            "snapshot the evidence."),
        confidence_label=_conf(f))


def _explain_api(f: Any) -> RiskExplanation:
    return RiskExplanation(
        what_happened=f"WebHound mapped part of your API surface ({_title(f)}).",
        why_it_matters=(
            "Knowing which endpoints your site exposes is what an attacker "
            "does first. Most of this is normal inventory; admin-style "
            "endpoints reachable anonymously deserve a closer look."),
        what_could_happen=(
            "An exposed admin or internal endpoint without server-side "
            "authorization could be called directly by anyone."),
        what_should_be_done=(
            "Confirm each endpoint enforces authentication and rate "
            "limiting server-side, and that error responses don't leak "
            "internal details."),
        confidence_label=_conf(f))


def _generic(f: Any) -> RiskExplanation:
    ftype = finding_type_of(f)
    if ftype == "inventory":
        return RiskExplanation(
            what_happened=f"WebHound recorded a discovered asset ({_title(f)}).",
            why_it_matters=(
                "This is inventory for your visibility — it is not a "
                "security problem on its own."),
            what_could_happen="No direct risk from this item.",
            what_should_be_done=(
                "Keep it in your asset inventory; no action needed unless "
                "it's unexpected."),
            confidence_label=_conf(f))
    if ftype == "hardening":
        return RiskExplanation(
            what_happened=f"A best-practice gap was found ({_title(f)}).",
            why_it_matters=(
                "Closing it strengthens your defense-in-depth. It is a "
                "hardening recommendation, not an active vulnerability."),
            what_could_happen=(
                "Low direct impact, but it reduces the safety margin if "
                "another issue arises."),
            what_should_be_done="Address it as part of routine hardening.",
            confidence_label=_conf(f))
    return RiskExplanation(
        what_happened=f"WebHound found an issue worth reviewing ({_title(f)}).",
        why_it_matters=(
            "It was flagged because it deviates from a secure "
            "configuration or expected behaviour."),
        what_could_happen=(
            "Depending on context, it could be leveraged as part of an "
            "attack."),
        what_should_be_done=(
            "Review the finding's evidence and remediate per the "
            "recommendation."),
        confidence_label=_conf(f))


_ENGINE_BUILDERS = {
    "sensitive_paths": _explain_sensitive_path,
    "cookie_scanner": _explain_cookie,
    "security_headers": _explain_headers,
    "csp_engine": _explain_headers,
    "cors": _explain_headers,
    "form_risk": _explain_form,
    "input_analysis": _explain_form,
    "threat_intel": _explain_threat_intel,
    "third_party_domains": _explain_threat_intel,
    "injected_js": _explain_compromise,
    "hidden_iframes": _explain_compromise,
    "suspicious_redirects": _explain_compromise,
    "obfuscation_detector": _explain_compromise,
    "endpoint_discovery": _explain_api,
}

_CATEGORY_BUILDERS = {
    "security_header": _explain_headers,
    "cookie": _explain_cookie,
    "form": _explain_form,
    "compromise": _explain_compromise,
    "api": _explain_api,
}


def explain_finding(f: Any) -> RiskExplanation:
    """Return the four-part explanation for one finding."""
    # Inventory always gets the calm, no-risk explanation regardless of
    # which engine produced it (an inventory API finding is still
    # inventory, not an API risk).
    if finding_type_of(f) == "inventory":
        return _generic(f)
    builder = _ENGINE_BUILDERS.get(_engine(f))
    if builder is not None:
        return builder(f)
    builder = _CATEGORY_BUILDERS.get(_category(f))
    if builder is not None:
        return builder(f)
    return _generic(f)
