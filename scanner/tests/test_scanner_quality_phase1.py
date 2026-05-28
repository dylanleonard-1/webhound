"""Scanner accuracy fixes — Phase 1 (sensitive_paths + threat_intel + obfuscation).

Covers the regressions / false positives the user surfaced from the deep
scan of webhoundsecurity.com:

* sensitive_paths: 403-only no longer fabricates findings when the server
  returns 403 for every missing path; 200 without indicator + matching
  catch-all body is suppressed; 200 with confirmed indicator still fires.
* domain_classifier: vercel.link is TRUSTED (allowlist); risky-TLD alone
  doesn't push a domain into RISKY.
* obfuscation_detector: a base64 blob on its own is LOW + heuristic; the
  same blob next to eval + decoder + network signals escalates to MEDIUM.
* Finding.quality_label maps confidence + severity + tags to the label
  the dashboard renders.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from datetime import datetime, timezone

from webhound.core.extractor import PageArtifacts


def _mk_artifacts(
    *, url: str = "https://example.com/",
    inline_scripts: list[str] | None = None,
    external_links: list[str] | None = None,
    external_script_urls: list[str] | None = None,
    external_stylesheet_urls: list[str] | None = None,
    external_image_urls: list[str] | None = None,
    inline_js_request_urls: list[str] | None = None,
    inline_css_import_urls: list[str] | None = None,
) -> PageArtifacts:
    """Build a minimal PageArtifacts for engine tests. All fields the engines
    look at are settable; everything else gets a sensible default."""
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="t",
        all_links=[], internal_links=[],
        external_links=external_links or [],
        scripts=[], inline_scripts=inline_scripts or [],
        external_script_urls=external_script_urls or [],
        forms=[], cookies=[], response_headers={}, meta_tags={},
        extracted_at=datetime.now(timezone.utc),
        external_image_urls=external_image_urls or [],
        external_stylesheet_urls=external_stylesheet_urls or [],
        inline_css_import_urls=inline_css_import_urls or [],
        inline_js_request_urls=inline_js_request_urls or [],
    )
from webhound.core.scope import ScopeChecker
from webhound.engines.javascript.obfuscation_detector import (
    ObfuscationDetectorEngine,
)
from webhound.engines.recon.sensitive_paths import SensitivePathsEngine
from webhound.engines.threat_intel.external_domains import ThreatIntelEngine
from webhound.models.finding import Finding, FindingCategory
from webhound.models.severity import Severity
from webhound.models.target import Target
from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassifier,
)

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# In-memory SafeHttpClient stub — programmable per-URL responses.
# ---------------------------------------------------------------------------


@dataclass
class _Resp:
    status_code: int
    body: str = ""
    content_type: str = "text/html"
    failed: bool = False


class _StubClient:
    """Minimal stand-in for SafeHttpClient. Configure with a per-URL map of
    (HEAD, GET) responses; anything not mapped → 404."""

    def __init__(self, *, head: dict[str, _Resp] | None = None,
                 get: dict[str, _Resp] | None = None,
                 default: _Resp | None = None) -> None:
        self._head = head or {}
        self._get = get or {}
        self._default = default or _Resp(status_code=404)

    async def head(self, url: str) -> _Resp:
        return self._head.get(url, self._default)

    async def get(self, url: str) -> _Resp:
        return self._get.get(url, self._default)


def _target() -> Target:
    return Target.from_url("https://example.com")


# ---------------------------------------------------------------------------
# sensitive_paths
# ---------------------------------------------------------------------------


async def test_sensitive_paths_403_for_every_missing_path_is_suppressed():
    """If the calibration probes show the server returns 403 for any
    nonexistent path, a 403 on /.env is not a finding."""
    target = _target()
    # All baseline probes AND all real paths return 403 → catch-all 403.
    client = _StubClient(default=_Resp(status_code=403))
    findings = await SensitivePathsEngine().probe(target, client,
                                                   ScopeChecker(target))
    # Zero status-only findings. (Some 200-bodied tests might still emit
    # things, but with everything 403, we expect a clean queue.)
    assert findings == []


async def test_sensitive_paths_403_passes_when_baseline_is_404():
    """If the calibration probes get 404s (server tells you missing paths
    are missing) but the real path returns 403, that 403 IS a weak signal —
    surface it as a heuristic INFO finding."""
    target = _target()
    head_map = {
        # Calibration probes return 404 → baseline does NOT suppress 403.
        "https://example.com/__wh_probe_a_4f3d1c.html": _Resp(404),
        "https://example.com/__wh_probe_b_8e21bb.html": _Resp(404),
        "https://example.com/__wh_probe_c_a907de.html": _Resp(404),
        # /.git/config is HIGH-severity-eligible — returns 403.
        "https://example.com/.git/config": _Resp(403),
    }
    client = _StubClient(head=head_map, default=_Resp(404))
    findings = await SensitivePathsEngine().probe(target, client,
                                                   ScopeChecker(target))
    # We should get exactly one heuristic-tagged 403 finding for .git/config.
    git_findings = [f for f in findings if "/.git/config" in (f.metadata.get("url") or "")]
    assert len(git_findings) == 1
    f = git_findings[0]
    assert f.severity == Severity.INFO
    assert f.confidence < 0.5
    assert "heuristic" in (f.tags or [])
    assert f.quality_label == "informational" or f.quality_label == "advisory"


async def test_sensitive_paths_200_with_indicator_still_fires():
    """The happy path: a real .env is exposed (200 + key=value body). The
    new accuracy guardrails must not break this."""
    target = _target()
    head_map = {
        "https://example.com/__wh_probe_a_4f3d1c.html": _Resp(404),
        "https://example.com/__wh_probe_b_8e21bb.html": _Resp(404),
        "https://example.com/__wh_probe_c_a907de.html": _Resp(404),
        "https://example.com/.env": _Resp(200, content_type="text/plain"),
    }
    body = "DB_PASSWORD=hunter2\nAPI_KEY=sk_test_123\nSECRET=foobar\n"
    get_map = {
        "https://example.com/.env": _Resp(200, body=body, content_type="text/plain"),
    }
    client = _StubClient(head=head_map, get=get_map, default=_Resp(404))
    findings = await SensitivePathsEngine().probe(target, client,
                                                   ScopeChecker(target))
    env_findings = [f for f in findings if (f.metadata.get("path") == "/.env")]
    assert len(env_findings) == 1
    assert env_findings[0].severity == Severity.CRITICAL
    assert env_findings[0].confidence >= 0.85
    # The body got masked — no plaintext password leaks into evidence.
    ev = env_findings[0].evidence[0].content
    assert "hunter2" not in ev
    assert "***" in ev


async def test_sensitive_paths_200_catch_all_shell_is_suppressed():
    """SPA fallback: server returns 200 with the same HTML shell for any
    unknown path. /admin returning that shell isn't an admin panel."""
    target = _target()
    spa_shell = "<html><body><div id='root'></div><script src='/app.js'></script></body></html>" * 5
    head_map = {
        "https://example.com/__wh_probe_a_4f3d1c.html": _Resp(200),
        "https://example.com/__wh_probe_b_8e21bb.html": _Resp(200),
        "https://example.com/__wh_probe_c_a907de.html": _Resp(200),
        "https://example.com/admin": _Resp(200),
    }
    get_map = {
        "https://example.com/__wh_probe_a_4f3d1c.html": _Resp(200, body=spa_shell),
        "https://example.com/__wh_probe_b_8e21bb.html": _Resp(200, body=spa_shell),
        "https://example.com/__wh_probe_c_a907de.html": _Resp(200, body=spa_shell),
        # /admin returns the exact same SPA shell → not a real admin panel.
        "https://example.com/admin": _Resp(200, body=spa_shell),
    }
    client = _StubClient(head=head_map, get=get_map, default=_Resp(404))
    findings = await SensitivePathsEngine().probe(target, client,
                                                   ScopeChecker(target))
    admin_findings = [f for f in findings if (f.metadata.get("path") == "/admin")]
    assert admin_findings == []


# ---------------------------------------------------------------------------
# threat_intel / domain_classifier
# ---------------------------------------------------------------------------


def test_classifier_vercel_link_is_trusted_not_risky():
    """`.link` is in the abuse-prone TLD list, but vercel.link is a known
    legitimate platform domain — the explicit allowlist must overrule the
    TLD heuristic."""
    result = DomainClassifier().classify("preview-app.vercel.link")
    assert result.classification == DomainClass.TRUSTED
    # And the same for the core Vercel domains.
    assert DomainClassifier().classify("my-app.vercel.app").classification == DomainClass.TRUSTED
    assert DomainClassifier().classify("vercel.com").classification == DomainClass.TRUSTED


def test_classifier_risky_tld_alone_does_not_push_to_risky():
    """The weight downgrade ensures a random domain on a risky TLD lands
    in SUSPICIOUS, not RISKY. RISKY now needs a second corroborating signal."""
    # Made-up domain on a risky TLD, no other signals.
    result = DomainClassifier().classify("totally-random-thing.xyz")
    assert result.classification.value in {"suspicious", "common_benign", "unknown"}
    # NOT risky.
    assert result.classification != DomainClass.RISKY


def test_classifier_risky_tld_plus_keyword_still_risky():
    """Two converging weak signals → RISKY. We're downgrading the
    one-signal case, not turning the engine off."""
    result = DomainClassifier().classify("secure-login-update.xyz")
    # risky_tld (2.5) + suspicious_keyword (2.0) = 4.5 → RISKY.
    assert result.classification == DomainClass.RISKY


async def test_threat_intel_engine_does_not_flag_vercel_link_high():
    """End-to-end: artifacts that reference vercel.link must NOT produce a
    HIGH 'compromise' finding from threat_intel."""
    artifacts = _mk_artifacts(
        url="https://webhoundsecurity.com/",
        external_links=["https://preview.vercel.link/build"],
    )
    findings = await ThreatIntelEngine().analyze(artifacts)
    high_risk = [f for f in findings
                 if f.category == FindingCategory.COMPROMISE
                 and f.severity.rank >= Severity.HIGH.rank]
    assert high_risk == [], (
        f"Expected no HIGH+ compromise findings for vercel.link, got: "
        f"{[f.title for f in high_risk]}"
    )


# ---------------------------------------------------------------------------
# obfuscation_detector
# ---------------------------------------------------------------------------


def test_obfuscation_base64_alone_is_low_heuristic():
    """A standalone base64 blob (no eval/decoder/network/secret) is a weak
    signal — must land at LOW + heuristic, not MEDIUM."""
    # 200 chars of base64-alphabet padding-looking content.
    blob = "A" * 200
    script = f"var x = '{blob}';"
    artifacts = _mk_artifacts(inline_scripts=[script])
    findings = ObfuscationDetectorEngine().analyze(artifacts)
    b64 = [f for f in findings if "base64" in f.title.lower()]
    assert len(b64) == 1
    assert b64[0].severity == Severity.LOW
    assert b64[0].confidence < 0.55
    assert b64[0].quality_label == "heuristic"


def test_obfuscation_base64_plus_one_corroborator_is_medium():
    """Base64 blob + any single corroborator (eval / decoder / network /
    credential) → MEDIUM + 'likely'. This is the corroborated case we
    actually WANT to surface; the standalone-base64 case stays LOW above."""
    blob = "A" * 200
    script = f"""
    eval(atob('{blob}'));
    fetch('/exfil', {{method: 'POST', body: navigator.userAgent}});
    """
    artifacts = _mk_artifacts(inline_scripts=[script])
    findings = ObfuscationDetectorEngine().analyze(artifacts)
    b64 = [f for f in findings if "base64" in f.title.lower()]
    assert len(b64) == 1
    assert b64[0].severity == Severity.MEDIUM
    assert b64[0].confidence >= 0.65
    assert b64[0].quality_label in {"likely", "confirmed"}


# ---------------------------------------------------------------------------
# Finding.quality_label
# ---------------------------------------------------------------------------


def test_quality_label_derivation():
    """The five quality labels cover the dashboard's UI categories."""
    def f(severity, confidence, tags=()):
        return Finding(
            title="t", description="d", severity=severity,
            confidence=confidence, tags=list(tags),
            scanner_engine="test", category=FindingCategory.UNKNOWN,
        )

    assert f(Severity.HIGH, 0.95).quality_label == "confirmed"
    assert f(Severity.HIGH, 0.75).quality_label == "likely"
    assert f(Severity.HIGH, 0.50).quality_label == "heuristic"
    assert f(Severity.MEDIUM, 0.85, tags=["heuristic"]).quality_label == "heuristic"
    assert f(Severity.INFO, 0.95).quality_label == "informational"
    assert f(Severity.INFO, 0.95, tags=["advisory"]).quality_label == "advisory"
