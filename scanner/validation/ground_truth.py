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
)


ALL_TARGETS: tuple[GroundTruthTarget, ...] = _CLEAN + _VULN + _COMPROMISED
CLEAN_TARGETS = _CLEAN
VULNERABLE_TARGETS = _VULN
COMPROMISED_TARGETS = _COMPROMISED


def targets_by_category(category: str) -> tuple[GroundTruthTarget, ...]:
    return tuple(t for t in ALL_TARGETS if t.category == category)


def target_by_name(name: str) -> GroundTruthTarget | None:
    return next((t for t in ALL_TARGETS if t.name == name), None)
