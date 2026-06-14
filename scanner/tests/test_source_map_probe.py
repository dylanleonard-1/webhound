# WebHound — scanner/tests/test_source_map_probe.py
# Phase 9B: Unit tests for the source_map_probe engine.
# Previously STATIC-only — this file brings it to full unit-test coverage.
# Uses a mock HTTP client — no live network required.

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from webhound.core.extractor import PageArtifacts
from webhound.engines.javascript.source_map_probe import SourceMapProbeEngine
from webhound.models.severity import Severity

_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Mock HTTP client
# ---------------------------------------------------------------------------

@dataclass
class _MockResponse:
    status_code: int
    failed: bool = False


class _MockClient:
    """Minimal mock of SafeHttpClient that returns preset responses."""

    def __init__(self, responses: dict[str, _MockResponse]) -> None:
        self._responses = responses

    async def head(self, url: str) -> _MockResponse:
        return self._responses.get(url, _MockResponse(status_code=404))


def _client_returning(url_to_status: dict[str, int]) -> _MockClient:
    return _MockClient({
        url: _MockResponse(status_code=status, failed=(status >= 400))
        for url, status in url_to_status.items()
    })


def _always_200() -> _MockClient:
    """Returns 200 for any URL."""
    class _Always(_MockClient):
        async def head(self, url: str) -> _MockResponse:
            return _MockResponse(status_code=200, failed=False)
    return _Always({})


def _always_404() -> _MockClient:
    class _Never(_MockClient):
        async def head(self, url: str) -> _MockResponse:
            return _MockResponse(status_code=404, failed=True)
    return _Never({})


def _always_error() -> _MockClient:
    """Simulates network failure."""
    class _Error(_MockClient):
        async def head(self, url: str) -> _MockResponse:
            raise ConnectionError("network error")
    return _Error({})


# ---------------------------------------------------------------------------
# PageArtifacts helpers
# ---------------------------------------------------------------------------

def _artifacts(
    url: str = "https://example.com/",
    inline_scripts: list[str] | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test",
        all_links=[],
        internal_links=[],
        external_links=[],
        scripts=[],
        inline_scripts=inline_scripts or [],
        external_script_urls=[],
        forms=[],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=_NOW,
    )


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

class TestSourceMapProbeDetection:
    def test_accessible_source_map_fires(self):
        a = _artifacts(inline_scripts=["var x=1;\n//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert len(findings) == 1
        assert "Source map is publicly accessible" in findings[0].title

    def test_inaccessible_source_map_no_finding(self):
        a = _artifacts(inline_scripts=["var x=1;\n//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_404())
        findings = _run(engine.analyze(a))
        assert findings == []

    def test_network_error_no_finding(self):
        a = _artifacts(inline_scripts=["var x=1;\n//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_error())
        findings = _run(engine.analyze(a))
        assert findings == []

    def test_no_source_map_comment_no_finding(self):
        a = _artifacts(inline_scripts=["var x=1; var y=2;"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings == []

    def test_empty_inline_scripts_no_finding(self):
        a = _artifacts(inline_scripts=[])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings == []


# ---------------------------------------------------------------------------
# URL resolution
# ---------------------------------------------------------------------------

class TestSourceMapUrlResolution:
    def test_relative_map_url_resolved(self):
        a = _artifacts(
            url="https://example.com/js/bundle.js",
            inline_scripts=["//# sourceMappingURL=bundle.js.map"],
        )
        probed: list[str] = []

        class _Record(_MockClient):
            async def head(self, url: str) -> _MockResponse:
                probed.append(url)
                return _MockResponse(status_code=200, failed=False)

        engine = SourceMapProbeEngine(client=_Record({}))
        _run(engine.analyze(a))
        assert any("bundle.js.map" in u for u in probed)

    def test_absolute_map_url_used_as_is(self):
        abs_url = "https://cdn.example.com/maps/bundle.js.map"
        a = _artifacts(
            url="https://example.com/",
            inline_scripts=[f"//# sourceMappingURL={abs_url}"],
        )
        probed: list[str] = []

        class _Record(_MockClient):
            async def head(self, url: str) -> _MockResponse:
                probed.append(url)
                return _MockResponse(status_code=200, failed=False)

        engine = SourceMapProbeEngine(client=_Record({}))
        _run(engine.analyze(a))
        assert abs_url in probed


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_map_url_in_two_scripts_probed_once(self):
        a = _artifacts(inline_scripts=[
            "//# sourceMappingURL=app.js.map",
            "// something else\n//# sourceMappingURL=app.js.map",
        ])
        probed: list[str] = []

        class _Record(_MockClient):
            async def head(self, url: str) -> _MockResponse:
                probed.append(url)
                return _MockResponse(status_code=200, failed=False)

        engine = SourceMapProbeEngine(client=_Record({}))
        findings = _run(engine.analyze(a))
        assert probed.count(probed[0]) == 1
        assert len(findings) == 1

    def test_two_different_map_urls_both_probed(self):
        a = _artifacts(inline_scripts=[
            "//# sourceMappingURL=app1.js.map",
            "//# sourceMappingURL=app2.js.map",
        ])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Legacy //@ sourceMappingURL syntax
# ---------------------------------------------------------------------------

class TestLegacySyntax:
    def test_legacy_at_sign_detected(self):
        a = _artifacts(inline_scripts=["var x=1;\n//@ sourceMappingURL=bundle.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Finding quality
# ---------------------------------------------------------------------------

class TestFindingQuality:
    def test_finding_severity_medium(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].severity == Severity.MEDIUM

    def test_finding_confidence_high(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].confidence >= 0.9

    def test_finding_has_evidence(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].evidence

    def test_finding_has_framework(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].framework is not None

    def test_finding_engine_name(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].scanner_engine == "source_map_probe"

    def test_evidence_includes_http_status(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert "200" in findings[0].evidence[0].content

    def test_map_url_in_metadata(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert "map_url" in findings[0].metadata

    def test_remediation_present(self):
        a = _artifacts(inline_scripts=["//# sourceMappingURL=app.js.map"])
        engine = SourceMapProbeEngine(client=_always_200())
        findings = _run(engine.analyze(a))
        assert findings[0].remediation
