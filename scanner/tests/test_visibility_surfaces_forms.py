# WebHound — scanner/tests/test_visibility_surfaces_forms.py
# Phase 5 tests: forms inventory + classification section. Reuses the real
# FormDiscoveryEngine via PageArtifacts built from real HTML. No network.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webhound.core.extractor import Extractor
from webhound.core.http_client import HttpResponse
from webhound.core.visibility.surfaces import build_forms_section


def _artifacts(url: str, html: str):
    resp = HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=200,
        headers={"content-type": "text/html"},
        body=html,
        content_type="text/html",
        elapsed_ms=10.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )
    return Extractor().extract(resp)


class _Result:
    def __init__(self, artifacts):
        self.artifacts = artifacts


def _crawl(*pages):
    return [_Result(_artifacts(u, h)) for u, h in pages]


def test_classifies_login_search_upload_forms():
    results = _crawl(
        ("https://example.com/login",
         '<form method="POST" action="/auth">'
         '<input name="user"><input name="pass" type="password"></form>'),
        ("https://example.com/search",
         '<form method="GET" action="/results"><input name="q"></form>'),
        ("https://example.com/upload",
         '<form method="POST" action="/u">'
         '<input name="file" type="file"></form>'),
    )
    section = build_forms_section(results)
    assert section["count"] == 3
    assert section["login_forms"] == 1
    assert section["search_forms"] == 1
    assert section["upload_forms"] == 1
    assert section["by_method"]["POST"] == 2
    assert section["by_method"]["GET"] == 1


def test_external_action_domain_recorded():
    results = _crawl(
        ("https://example.com/contact",
         '<form method="POST" action="https://forms.vendor.com/submit">'
         '<input name="email"></form>'),
    )
    section = build_forms_section(results)
    assert "forms.vendor.com" in section["external_action_domains"]
    # email field with no password → classified contact.
    assert section["by_type"].get("contact") == 1


def test_payment_form_classification():
    results = _crawl(
        ("https://example.com/checkout",
         '<form method="POST" action="/pay">'
         '<input name="card_number"><input name="cvv"></form>'),
    )
    section = build_forms_section(results)
    assert section["payment_forms"] == 1


def test_empty_when_no_forms():
    results = _crawl(("https://example.com/", "<p>no forms here</p>"))
    section = build_forms_section(results)
    assert section["count"] == 0
    assert section["samples"] == []


def test_handles_result_without_artifacts():
    class _Empty:
        artifacts = None

    section = build_forms_section([_Empty()])
    assert section["count"] == 0
