# WebHound — apps/api/services/provider_access_registry.py
# Phase-2 Platform Access Framework: the SINGLE config-driven registry of CDN/WAF
# providers. Detection signals, automation capability, allowlist method, and the
# full remediation workflow all live here as DATA — so adding a provider is a
# config entry, never new code. The detector, the wizard payload builder, the
# Cloudflare/Vercel access services, and the admin view all read this registry.
#
# Scanner IPs are NEVER hardcoded here — remediation steps carry an {ips}
# placeholder that is rendered at request time from config.scanner_outbound_ips().
#
# Detection signals are LIFTED from the existing detectors (no new detection
# logic invented): webhound.browser.challenge_detection._PROVIDER_SIGNATURES and
# webhound.providers.discovery._HEADER_CDNWAF_FALLBACK.
#
# Safe: pure data + pure functions. No network, no secrets.

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionSignals:
    """How to recognize this provider from an HTTP response. All matching is
    case-insensitive; presence of any header name OR any (header, value)
    substring OR any challenge marker contributes to detection."""

    # Header NAMES whose mere presence strongly implies the provider.
    headers: tuple[str, ...] = ()
    # (header_name, value_substring) pairs — e.g. ("server", "cloudflare").
    header_values: tuple[tuple[str, str], ...] = ()
    # Set-Cookie name fragments — e.g. "visid_incap" (Imperva).
    cookies: tuple[str, ...] = ()
    # Challenge/block fingerprints in the response URL chain.
    challenge_url: tuple[str, ...] = ()
    # Challenge/block fingerprints in the response HTML body.
    challenge_html: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationStep:
    """One step in the guided remediation. ``ips`` marks the step that contains
    the scanner IPs (the wizard renders a copy button on it)."""

    text: str            # may contain the literal "{ips}" placeholder
    ips: bool = False    # this step's payload is the scanner IP list


@dataclass(frozen=True)
class ProviderAccess:
    key: str
    name: str
    # Can WebHound fully self-serve allowlisting (OAuth + API)? Only true where
    # we genuinely automate — never fake automation.
    automation_capable: bool
    allowlist_method: str           # "api" | "manual"
    verification_method: str        # "scan_recheck" (reuse access-validation/run)
    support_url: str
    detection: DetectionSignals
    # Remediation workflow (rendered into a structured payload for the wizard).
    remediation_title: str
    remediation_problem: str
    remediation_impact: str
    remediation_steps: tuple[RemediationStep, ...]
    remediation_verification: str
    capabilities: tuple[str, ...] = field(default_factory=tuple)


# A reusable closing step for every manual provider.
def _verify_step() -> RemediationStep:
    return RemediationStep(
        "Return to WebHound and click “Verify Access” — we re-scan "
        "to confirm the scanner now gets through.")


_IP_STEP = RemediationStep(
    "Allowlist the WebHound scanner IPs (allow / bypass — never block): {ips}",
    ips=True)


# ---------------------------------------------------------------------------
# THE REGISTRY — 10 providers. New provider = a new entry here, no code change.
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, ProviderAccess] = {
    "cloudflare": ProviderAccess(
        key="cloudflare", name="Cloudflare",
        automation_capable=True, allowlist_method="api",
        verification_method="scan_recheck",
        support_url="https://dash.cloudflare.com/",
        capabilities=("oauth", "ip_allow_rule", "ua_skip_rule", "auto_update"),
        detection=DetectionSignals(
            headers=("cf-ray", "cf-mitigated"),
            header_values=(("server", "cloudflare"),),
            challenge_url=("/cdn-cgi/challenge-platform/", "challenges.cloudflare.com",
                           "/cdn-cgi/l/chk_jschl", "__cf_chl", "cf_chl_"),
            challenge_html=("checking your browser before accessing",
                            "cf-browser-verification", "__cf_chl_opt",
                            "attention required! | cloudflare", "cf-challenge-running"),
        ),
        remediation_title="Cloudflare is challenging the scanner",
        remediation_problem="Cloudflare's bot protection is serving a challenge to the "
                            "WebHound scanner before it can reach your site.",
        remediation_impact="The scan can only see the challenge page, not your real "
                           "application — coverage is near zero.",
        remediation_steps=(
            RemediationStep("Connect Cloudflare in WebHound — we create an IP-allow "
                            "rule for the scanner automatically (recommended)."),
            _IP_STEP,
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "vercel": ProviderAccess(
        key="vercel", name="Vercel",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://vercel.com/dashboard",
        capabilities=("ip_system_bypass_manual",),
        detection=DetectionSignals(
            headers=("x-vercel-id", "x-vercel-cache"),
            header_values=(("server", "vercel"),),
            challenge_url=(".well-known/vercel/security", "challenge.v2.wasm",
                           "/request-challenge", "/_vercel/security"),
            challenge_html=("vercel security checkpoint",),
        ),
        remediation_title="Vercel Security Checkpoint is blocking the scanner",
        remediation_problem="Vercel's Attack Challenge / Security Checkpoint is blocking "
                           "the WebHound scanner.",
        remediation_impact="The scanner is stopped at the checkpoint and cannot crawl "
                          "your pages.",
        remediation_steps=(
            RemediationStep("Open your Vercel dashboard and select the project for this site."),
            RemediationStep("Go to Settings → Firewall → System Bypasses "
                            "(DDoS Mitigations & System Bypasses)."),
            RemediationStep("Click “Add Bypass Rule” → Source IP."),
            _IP_STEP,
            RemediationStep("Save the rule, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "cloudfront": ProviderAccess(
        key="cloudfront", name="AWS CloudFront",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://console.aws.amazon.com/cloudfront/",
        detection=DetectionSignals(
            headers=("x-amz-cf-id", "x-amz-cf-pop"),
            header_values=(("via", "cloudfront"), ("server", "cloudfront")),
        ),
        remediation_title="AWS CloudFront / WAF is blocking the scanner",
        remediation_problem="A WAF in front of CloudFront is blocking the WebHound "
                           "scanner's requests.",
        remediation_impact="Requests are rejected at the edge before reaching your origin.",
        remediation_steps=(
            RemediationStep("Open AWS WAF → the Web ACL attached to your CloudFront "
                            "distribution."),
            RemediationStep("Add a rule with action ALLOW, matching the source IPs below, "
                            "placed ABOVE any blocking rules."),
            _IP_STEP,
            RemediationStep("Save and let the Web ACL propagate, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "akamai": ProviderAccess(
        key="akamai", name="Akamai",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://control.akamai.com/",
        detection=DetectionSignals(
            headers=("x-akamai-transformed", "akamai-grn"),
            header_values=(("server", "akamaighost"),),
            challenge_url=("/_bm/", "/akam/", "bm-verify", "/_sec/cp_challenge"),
            challenge_html=("akamai bot manager", "errors.edgesuite.net",
                            "you don't have permission to access"),
        ),
        remediation_title="Akamai Bot Manager is blocking the scanner",
        remediation_problem="Akamai (Bot Manager / Kona) is challenging or denying the "
                           "WebHound scanner.",
        remediation_impact="The scanner is denied at the Akamai edge.",
        remediation_steps=(
            RemediationStep("In Akamai Control Center, open the Security Configuration / "
                            "Bot Manager policy for this property."),
            RemediationStep("Add the scanner IPs to a network list and set the matching "
                            "policy action to ALLOW (allowlist)."),
            _IP_STEP,
            RemediationStep("Activate the configuration on staging → production, then "
                            "return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "fastly": ProviderAccess(
        key="fastly", name="Fastly",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://manage.fastly.com/",
        detection=DetectionSignals(
            headers=("x-fastly-request-id", "fastly-restarts"),
            header_values=(("x-served-by", "fastly"), ("via", "varnish")),
            challenge_html=("request blocked", "fastly error", "varnish cache server"),
        ),
        remediation_title="Fastly / Signal Sciences is blocking the scanner",
        remediation_problem="Fastly's WAF (Signal Sciences / Next-Gen WAF) is blocking "
                           "the WebHound scanner.",
        remediation_impact="Requests are blocked at the Fastly edge.",
        remediation_steps=(
            RemediationStep("Open the Fastly / Signal Sciences console for this site."),
            RemediationStep("Add the scanner IPs to the allowlist (Site → Rules → "
                            "Allowlist, or an ALLOW request rule)."),
            _IP_STEP,
            RemediationStep("Save / deploy the change, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "azure_front_door": ProviderAccess(
        key="azure_front_door", name="Azure Front Door",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://portal.azure.com/",
        detection=DetectionSignals(
            headers=("x-azure-ref", "x-azure-fdid", "x-fd-int-roxy-purgeid"),
            header_values=(("server", "microsoft-azure"),),
        ),
        remediation_title="Azure Front Door / WAF is blocking the scanner",
        remediation_problem="An Azure WAF policy on Front Door / Application Gateway is "
                           "blocking the WebHound scanner.",
        remediation_impact="Requests are blocked by the Azure WAF before reaching your app.",
        remediation_steps=(
            RemediationStep("In the Azure Portal, open the WAF policy attached to your "
                            "Front Door / Application Gateway."),
            RemediationStep("Add a custom rule with action ALLOW and a match condition on "
                            "the source IP addresses below, at a low priority number "
                            "(evaluated first)."),
            _IP_STEP,
            RemediationStep("Save the policy, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "imperva": ProviderAccess(
        key="imperva", name="Imperva (Incapsula)",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://my.imperva.com/",
        detection=DetectionSignals(
            headers=("x-iinfo", "x-cdn"),
            header_values=(("x-cdn", "incapsula"),),
            cookies=("visid_incap", "incap_ses"),
            challenge_html=("incapsula incident", "powered by imperva",
                            "request unsuccessful"),
        ),
        remediation_title="Imperva (Incapsula) is blocking the scanner",
        remediation_problem="Imperva Cloud WAF (Incapsula) is challenging or blocking the "
                           "WebHound scanner.",
        remediation_impact="The scanner is blocked at the Imperva edge.",
        remediation_steps=(
            RemediationStep("In the Imperva console, open Website → Security → "
                            "IP allowlist (or a Policy with ALLOW action)."),
            RemediationStep("Add the scanner IPs as allowed sources."),
            _IP_STEP,
            RemediationStep("Apply the change, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "sucuri": ProviderAccess(
        key="sucuri", name="Sucuri",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://waf.sucuri.net/",
        detection=DetectionSignals(
            headers=("x-sucuri-id", "x-sucuri-cache"),
            header_values=(("server", "sucuri"),),
            challenge_html=("sucuri website firewall", "access denied - sucuri website firewall"),
        ),
        remediation_title="Sucuri Firewall is blocking the scanner",
        remediation_problem="The Sucuri Website Firewall (WAF) is blocking the WebHound "
                           "scanner.",
        remediation_impact="Requests are blocked at the Sucuri proxy.",
        remediation_steps=(
            RemediationStep("Log in to the Sucuri WAF dashboard for this site."),
            RemediationStep("Go to Settings → Access Control → Whitelist IP "
                            "Addresses."),
            _IP_STEP,
            RemediationStep("Save the allowlist, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "aws_waf": ProviderAccess(
        key="aws_waf", name="AWS WAF",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://console.aws.amazon.com/wafv2/",
        detection=DetectionSignals(
            headers=("x-amzn-requestid", "x-amzn-waf-action"),
            challenge_url=("token.awswaf.com", "captcha.awswaf.com", ".well-known/awswaf"),
            challenge_html=("aws waf", "request blocked"),
        ),
        remediation_title="AWS WAF is blocking the scanner",
        remediation_problem="An AWS WAF Web ACL (on ALB / API Gateway / CloudFront) is "
                           "blocking the WebHound scanner.",
        remediation_impact="Requests are blocked by the Web ACL.",
        remediation_steps=(
            RemediationStep("Open AWS WAF → the Web ACL protecting this resource."),
            RemediationStep("Create an IP set with the scanner IPs and add a rule with "
                            "action ALLOW above your blocking rules."),
            _IP_STEP,
            RemediationStep("Save the Web ACL, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
    "google_cloud_armor": ProviderAccess(
        key="google_cloud_armor", name="Google Cloud Armor",
        automation_capable=False, allowlist_method="manual",
        verification_method="scan_recheck",
        support_url="https://console.cloud.google.com/net-security/securitypolicies",
        detection=DetectionSignals(
            header_values=(("via", "google"), ("server", "google frontend")),
            challenge_html=("google cloud armor", "the request was blocked"),
        ),
        remediation_title="Google Cloud Armor is blocking the scanner",
        remediation_problem="A Cloud Armor security policy on your load balancer is "
                           "blocking the WebHound scanner.",
        remediation_impact="Requests are denied by the Cloud Armor policy.",
        remediation_steps=(
            RemediationStep("In Google Cloud Console, open Network Security → Cloud "
                            "Armor → the policy on your backend."),
            RemediationStep("Add a rule with action ALLOW matching the source IPs below, "
                            "with a lower priority number than your deny rules."),
            _IP_STEP,
            RemediationStep("Save the policy, then return to WebHound."),
            _verify_step(),
        ),
        remediation_verification="scan_recheck",
    ),
}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def get_provider(key: str) -> ProviderAccess | None:
    return PROVIDERS.get((key or "").strip().lower())


def _norm_headers(headers: dict | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[str(k).strip().lower()] = str(v).lower()
    return out


def detect_provider(
    *,
    headers: dict | None = None,
    body: str = "",
    url_chain: str = "",
    cookies: str = "",
) -> dict | None:
    """Registry-driven provider detection. Scores every provider's signals against
    the response and returns the best match as ``{provider, name, confidence,
    reason, signals[]}`` — or None if nothing matched. Pure + data-driven: adding
    a provider to PROVIDERS is enough, no code change here.

    Confidence (0-100): a distinctive header/cookie is the strongest signal (50),
    a (header, value) match is strong (40), a challenge fingerprint is medium (30
    url / 25 html). Signals are additive, capped at 100."""
    h = _norm_headers(headers)
    body_l = (body or "").lower()
    url_l = (url_chain or "").lower()
    cookie_l = (cookies or "").lower()

    best: dict | None = None
    for p in PROVIDERS.values():
        score = 0
        reasons: list[str] = []
        for name in p.detection.headers:
            if name.lower() in h:
                score += 50
                reasons.append(f"header:{name}")
        for name, val in p.detection.header_values:
            hv = h.get(name.lower())
            if hv is not None and val.lower() in hv:
                score += 40
                reasons.append(f"header:{name}~{val}")
        for ck in p.detection.cookies:
            if ck.lower() in cookie_l or ck.lower() in h.get("set-cookie", ""):
                score += 50
                reasons.append(f"cookie:{ck}")
        for pat in p.detection.challenge_url:
            if pat.lower() in url_l:
                score += 30
                reasons.append(f"url:{pat}")
        for pat in p.detection.challenge_html:
            if pat.lower() in body_l:
                score += 25
                reasons.append(f"html:{pat}")
        if score <= 0:
            continue
        score = min(100, score)
        if best is None or score > best["confidence"]:
            best = {
                "provider": p.key,
                "name": p.name,
                "confidence": score,
                "reason": ", ".join(reasons[:4]),
                "signals": reasons,
                "automation_capable": p.automation_capable,
                "allowlist_method": p.allowlist_method,
            }
    return best


def all_providers() -> list[ProviderAccess]:
    return list(PROVIDERS.values())


def render_remediation(provider_key: str, ips: list[str]) -> dict | None:
    """Render the registry's remediation workflow into a structured, wizard-ready
    payload with the scanner IPs (from scanner_outbound_ips()) substituted in.
    Returns None for an unknown provider. No provider-specific logic lives in the
    consumer — everything is data from the registry."""
    p = get_provider(provider_key)
    if p is None:
        return None
    ip_str = ", ".join(ips) if ips else "the WebHound scanner IPs"
    steps = []
    for i, s in enumerate(p.remediation_steps, 1):
        steps.append({
            "n": i,
            "text": s.text.replace("{ips}", ip_str),
            "copyable": s.ips,
            "copy_value": ip_str if s.ips else None,
        })
    return {
        "provider": p.key,
        "provider_name": p.name,
        "automation_capable": p.automation_capable,
        "allowlist_method": p.allowlist_method,
        "title": p.remediation_title,
        "problem": p.remediation_problem,
        "impact": p.remediation_impact,
        "steps": steps,
        "verification": p.remediation_verification,
        "support_url": p.support_url,
        "scanner_ips": list(ips),
        "copy_all": ", ".join(ips),
    }
