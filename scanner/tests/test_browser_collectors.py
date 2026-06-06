# WebHound — tests/test_browser_collectors.py
# Phase-6B collectors: rendered forms, rendered scripts, cookies,
# console/page errors. Fully mocked — no Playwright, no network.

from __future__ import annotations

import pytest

from webhound.browser.form_extractor import (
    parse_rendered_forms,
)
from webhound.browser.models import BrowserTelemetry
from webhound.browser.playwright_runner import _capture_cookies
from webhound.browser.script_collector import (
    parse_rendered_scripts,
)
from webhound.utils.hashing import sha256_hex


# ---------------------------------------------------------------------------
# Form extraction
# ---------------------------------------------------------------------------


def test_parse_rendered_forms_rich_fields() -> None:
    forms = parse_rendered_forms([{
        "action": "https://target.test/upload",
        "method": "post",
        "fields": [
            {"name": "doc", "type": "file"},
            {"name": "csrf", "type": "hidden"},
            {"name": "note", "type": "textarea"},
        ],
        "hasPassword": False,
        "hasFile": True,
        "hiddenNames": ["csrf"],
    }], page_url="https://target.test/app")
    assert len(forms) == 1
    f = forms[0]
    assert f.has_file_input is True
    assert f.hidden_field_names == ("csrf",)
    assert f.action_is_external is False
    assert f.page_url == "https://target.test/app"


def test_parse_rendered_forms_external_action_flagged() -> None:
    """A lazy-loaded form posting to a different registrable domain is
    exfil-shaped — the flag must be set. Same registrable domain
    (api.target.test from www.target.test) must NOT be flagged."""
    external, internal = parse_rendered_forms([
        {"action": "https://collector.evil.example/submit", "method": "POST"},
        {"action": "https://api.target.test/login", "method": "POST"},
    ], page_url="https://www.target.test/checkout")
    assert external.action_is_external is True
    assert internal.action_is_external is False


def test_parse_rendered_forms_junk_payload() -> None:
    assert parse_rendered_forms(None, page_url="x") == []
    assert parse_rendered_forms("nope", page_url="x") == []
    assert parse_rendered_forms([None, 7, "str"], page_url="x") == []


# ---------------------------------------------------------------------------
# Script collection
# ---------------------------------------------------------------------------


def test_parse_rendered_scripts_kinds() -> None:
    scripts = parse_rendered_scripts({
        "scripts": [
            {"src": "https://target.test/app.js", "module": False,
             "snippet": "", "textLength": 0},
            {"src": "https://target.test/chunk.mjs", "module": True,
             "snippet": "", "textLength": 0},
            {"src": None, "module": False,
             "snippet": "window.__ENV__={api:'x'}", "textLength": 24},
        ],
        "hints": [
            {"href": "https://target.test/lazy-chunk.js", "rel": "modulepreload"},
            {"href": "https://target.test/next.js", "rel": "prefetch"},
        ],
    })
    kinds = [s.kind for s in scripts]
    assert kinds == [
        "script_tag", "module", "inline", "modulepreload", "prefetch",
    ]
    inline = scripts[2]
    assert inline.is_inline is True
    assert inline.snippet_hash == sha256_hex("window.__ENV__={api:'x'}")
    assert inline.snippet_truncated is False


def test_parse_rendered_scripts_truncation_marked() -> None:
    scripts = parse_rendered_scripts({
        "scripts": [{"src": None, "module": False,
                     "snippet": "x" * 400, "textLength": 90_000}],
        "hints": [],
    })
    assert scripts[0].snippet_truncated is True


def test_parse_rendered_scripts_junk_payload() -> None:
    assert parse_rendered_scripts(None) == []
    assert parse_rendered_scripts([1, 2]) == []
    assert parse_rendered_scripts({"scripts": ["x", None]}) == []


# ---------------------------------------------------------------------------
# Cookie capture — values must never be stored
# ---------------------------------------------------------------------------


class _FakeContext:
    def __init__(self, cookies=None, raises=False):
        self._cookies = cookies or []
        self._raises = raises

    async def cookies(self, _url):
        if self._raises:
            raise RuntimeError("context closed")
        return self._cookies


@pytest.mark.asyncio
async def test_cookie_capture_never_stores_values() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    ctx = _FakeContext(cookies=[{
        "name": "session", "value": "SUPER-SECRET-TOKEN-VALUE",
        "domain": ".target.test", "path": "/", "secure": True,
        "httpOnly": True, "sameSite": "Lax",
    }])
    await _capture_cookies(ctx, tel, "https://target.test/")
    assert len(tel.browser_cookies) == 1
    c = tel.browser_cookies[0]
    assert c.name == "session"
    assert c.secure and c.http_only and c.same_site == "Lax"
    assert c.value_length == len("SUPER-SECRET-TOKEN-VALUE")
    # The actual value must not appear anywhere on the model.
    assert "SUPER-SECRET" not in repr(c)


@pytest.mark.asyncio
async def test_cookie_capture_failure_is_isolated() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    await _capture_cookies(_FakeContext(raises=True), tel,
                           "https://target.test/")
    assert tel.browser_cookies == []
    assert any("cookie capture failed" in e for e in tel.errors)
