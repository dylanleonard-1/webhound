# WebHound — scanner/tests/test_vulnerable_libs_wiring.py
# FIX 4: VulnerableLibsEngine wired into the orchestrator's scan-wide pass.
#
# Three layers of contract:
#   1. Profile/option configuration — gated to DEEP + ENTERPRISE.
#   2. Engine logic — outdated lib flagged, modern lib not (no FP).
#   3. Orchestrator integration — the pass runs in a deep scan, records
#      diagnostics, and an engine failure never fails the scan.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.core.scan_profiles import (
    DEEP, ENTERPRISE, MONITOR, QUICK, STANDARD,
)
from webhound.engines.javascript.vulnerable_libs import VulnerableLibsEngine
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.target import ScanOptions, Target


# ---------------------------------------------------------------------------
# 1. Profile / option configuration
# ---------------------------------------------------------------------------

def test_deep_and_enterprise_enable_vuln_libs():
    assert DEEP.vuln_libs_enabled is True
    assert ENTERPRISE.vuln_libs_enabled is True


def test_light_profiles_do_not_enable_vuln_libs():
    for p in (QUICK, STANDARD, MONITOR):
        assert p.vuln_libs_enabled is False, p.name


def test_profile_propagates_flag_to_scan_options():
    assert DEEP.to_scan_options().vuln_libs_enabled is True
    assert QUICK.to_scan_options().vuln_libs_enabled is False


def test_scan_options_default_vuln_libs_false():
    assert ScanOptions().vuln_libs_enabled is False


def test_summary_includes_vuln_libs_flag():
    assert DEEP.summary()["vuln_libs_enabled"] is True


# ---------------------------------------------------------------------------
# 2. Engine logic (pure)
# ---------------------------------------------------------------------------

def test_outdated_jquery_flagged():
    eng = VulnerableLibsEngine()
    findings = eng.analyze_script_urls(
        ["https://code.jquery.com/jquery-1.12.4.min.js"],
        page_url="https://example.com/",
    )
    assert len(findings) == 1
    assert "jQuery" in findings[0].title
    assert "1.12.4" in findings[0].title


def test_modern_jquery_not_flagged():
    """3.6.0 >= the 3.5.0 patch threshold — must not be a false positive."""
    eng = VulnerableLibsEngine()
    findings = eng.analyze_script_urls(
        ["https://code.jquery.com/jquery-3.6.0.min.js"],
        page_url="https://example.com/",
    )
    assert findings == []


def test_script_url_inventory_deduplicated():
    eng = VulnerableLibsEngine()
    findings = eng.analyze_script_urls(
        [
            "https://code.jquery.com/jquery-1.12.4.min.js",
            "https://cdn.example.com/jquery-1.12.4.min.js",  # same lib+ver
        ],
        page_url="https://example.com/",
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# 3. Orchestrator integration
# ---------------------------------------------------------------------------

def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls
    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com", connection_failed=True),
    )
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com", a=["93.184.216.34"]),
    )


def _transport(body: str) -> httpx.MockTransport:
    headers = {"content-type": "text/html; charset=utf-8"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(200, text=body, headers=headers)
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(handler)


def _deep_target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(
        max_pages=3, max_depth=1, rate_limit_rps=10.0,
        verify_tls=False, vuln_libs_enabled=True,
    )
    return Target.from_url(url, scan_options=opts)


_OUTDATED_HTML = (
    "<!DOCTYPE html><html><head><title>t</title>"
    '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>'
    "</head><body><p>hi</p></body></html>"
)
_MODERN_HTML = (
    "<!DOCTYPE html><html><head><title>t</title>"
    '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
    "</head><body><p>hi</p></body></html>"
)


@pytest.mark.anyio
async def test_deep_scan_runs_engine_and_flags_outdated_lib(monkeypatch):
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(_deep_target(), _transport=_transport(_OUTDATED_HTML))
    result = await scanner.scan()

    diag = result.metadata.get("vulnerable_libs")
    assert diag is not None and diag["ran"] is True
    assert diag["input_scripts"] >= 1
    assert "vulnerable_libs" in result.engines_run

    titles = " ".join(f.title for f in result.findings)
    assert "jQuery" in titles


@pytest.mark.anyio
async def test_modern_lib_no_false_positive(monkeypatch):
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(_deep_target(), _transport=_transport(_MODERN_HTML))
    result = await scanner.scan()

    diag = result.metadata.get("vulnerable_libs")
    assert diag is not None and diag["ran"] is True
    assert diag["findings"] == 0
    assert all(f.scanner_engine != "vulnerable_libs" for f in result.findings)


@pytest.mark.anyio
async def test_engine_disabled_when_profile_off(monkeypatch):
    _patch_tls_dns(monkeypatch)
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0,
                       verify_tls=False)  # vuln_libs_enabled defaults False
    target = Target.from_url("https://example.com", scan_options=opts)
    scanner = Scanner(target, _transport=_transport(_OUTDATED_HTML))
    result = await scanner.scan()

    diag = result.metadata.get("vulnerable_libs")
    assert diag is not None and diag["ran"] is False
    assert "vulnerable_libs" not in result.engines_run


@pytest.mark.anyio
async def test_engine_failure_does_not_fail_scan(monkeypatch):
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(_deep_target(), _transport=_transport(_OUTDATED_HTML))

    def _boom(*a, **k):
        raise RuntimeError("synthetic vuln-libs failure")

    monkeypatch.setattr(scanner._vuln_libs, "analyze_script_urls", _boom)
    result = await scanner.scan()

    # Scan still completes (not marked failed) and records the error.
    assert result.status.value != "failed"
    diag = result.metadata.get("vulnerable_libs")
    assert diag is not None and diag["ran"] is False
    assert diag["errors"] and "synthetic" in diag["errors"][0]
