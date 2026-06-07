# WebHound — tests/test_threat_intel_overlay.py
# Phase-13 integration: the live ThreatIntelEngine consumes feed hits +
# brand impersonation (the overlay), so the new reputation layer reaches
# real scan findings.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import PageArtifacts
from webhound.engines.threat_intel.external_domains import ThreatIntelEngine
from webhound.models.severity import Severity
from webhound.threat_intel import FeedManager
from webhound.threat_intel.feed_normalizer import normalize_urlhaus


def _artifacts(*, external_links=(), scripts=()) -> PageArtifacts:
    return PageArtifacts(
        url="https://t.test/", status_code=200, content_type="text/html",
        title=None, all_links=[], internal_links=[],
        external_links=list(external_links),
        scripts=[], inline_scripts=[],
        external_script_urls=list(scripts), forms=[], cookies=[],
        response_headers={}, meta_tags={},
        extracted_at=datetime.now(timezone.utc))


def _host_findings(findings):
    return [f for f in findings if f.scanner_engine == "threat_intel"
            and (f.metadata or {}).get("page_url") is None
            and "third-party host" in f.title]


@pytest.mark.anyio
async def test_feed_hit_escalates_to_critical() -> None:
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://evil-skim.test/a.js", "threat": "skimmer",
         "url_status": "online"}]))
    eng = ThreatIntelEngine(feed_manager=fm)
    findings = await eng.analyze(
        _artifacts(scripts=["https://evil-skim.test/a.js"]))
    crit = [f for f in findings
            if f.severity == Severity.CRITICAL and "evil-skim.test" in f.title]
    assert crit
    ev = crit[0].evidence[0]
    assert ev.extra.get("feed_hit")                     # overlay metadata present
    assert any("threat-feed hit" in s
               for s in ev.extra.get("signals", []))


@pytest.mark.anyio
async def test_impersonation_escalates_to_critical_offline() -> None:
    # No feed manager — impersonation overlay runs offline.
    eng = ThreatIntelEngine()
    findings = await eng.analyze(
        _artifacts(external_links=["https://paypa1.com/login"]))
    crit = [f for f in findings
            if f.severity == Severity.CRITICAL and "paypa1.com" in f.title]
    assert crit
    assert crit[0].evidence[0].extra.get("impersonation")


@pytest.mark.anyio
async def test_trusted_vendor_not_escalated() -> None:
    """Task 8: a trusted vendor with no feed hit / impersonation must NOT
    be escalated by the overlay."""
    eng = ThreatIntelEngine()
    findings = await eng.analyze(
        _artifacts(scripts=["https://js.stripe.com/v3/"]))
    flagged = [f for f in findings
               if f.severity.rank >= Severity.MEDIUM.rank
               and "stripe.com" in f.title]
    assert flagged == []


@pytest.mark.anyio
async def test_trusted_vendor_escalated_only_with_feed_context() -> None:
    """A trusted host normally stays quiet, but a real feed hit (e.g. a
    compromised CDN) is legitimate threat context and DOES escalate."""
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://js.stripe.com/compromised.js", "threat": "malware",
         "url_status": "online"}]))
    eng = ThreatIntelEngine(feed_manager=fm)
    findings = await eng.analyze(
        _artifacts(scripts=["https://js.stripe.com/v3/"]))
    crit = [f for f in findings
            if f.severity == Severity.CRITICAL and "stripe.com" in f.title]
    assert crit                                          # feed context wins


@pytest.mark.anyio
async def test_clean_unknown_host_not_escalated() -> None:
    eng = ThreatIntelEngine()
    findings = await eng.analyze(
        _artifacts(scripts=["https://acmewidgets.com/app.js"]))
    flagged = [f for f in findings
               if f.severity.rank >= Severity.MEDIUM.rank
               and "acmewidgets.com" in f.title]
    assert flagged == []
