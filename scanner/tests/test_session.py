# WebHound — scanner/tests/test_session.py
# Tests for Phase 20: SessionContext, parse_header, parse_cookie,
# SafeHttpClient session integration, and run_scan CLI session flags.

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from webhound.core.session_context import (
    SessionContext,
    _is_sensitive_header,
    _redact,
    parse_cookie,
    parse_header,
)
from webhound.core.http_client import SafeHttpClient
from webhound.core.retry_policy import NO_RETRY_POLICY
from webhound.models.target import ScanOptions


# ---------------------------------------------------------------------------
# parse_header
# ---------------------------------------------------------------------------


def test_parse_header_basic():
    name, value = parse_header("X-Custom: hello")
    assert name == "X-Custom"
    assert value == "hello"


def test_parse_header_strips_whitespace():
    name, value = parse_header("  X-Foo  :  bar baz  ")
    assert name == "X-Foo"
    assert value == "bar baz"


def test_parse_header_value_with_colon():
    name, value = parse_header("Authorization: Bearer tok:en")
    assert name == "Authorization"
    assert value == "Bearer tok:en"


def test_parse_header_missing_colon():
    with pytest.raises(ValueError, match="Expected 'Name: value'"):
        parse_header("NoColon")


def test_parse_header_empty_name():
    with pytest.raises(ValueError, match="name must not be empty"):
        parse_header(": value")


# ---------------------------------------------------------------------------
# parse_cookie
# ---------------------------------------------------------------------------


def test_parse_cookie_basic():
    name, value = parse_cookie("session=abc123")
    assert name == "session"
    assert value == "abc123"


def test_parse_cookie_value_with_equals():
    name, value = parse_cookie("token=abc=def")
    assert name == "token"
    assert value == "abc=def"


def test_parse_cookie_missing_equals():
    with pytest.raises(ValueError, match="Expected 'name=value'"):
        parse_cookie("nocookie")


def test_parse_cookie_empty_name():
    with pytest.raises(ValueError, match="name must not be empty"):
        parse_cookie("=value")


# ---------------------------------------------------------------------------
# _is_sensitive_header / _redact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "Authorization", "authorization", "AUTHORIZATION",
    "Cookie", "set-cookie",
    "X-Api-Key", "x-api-key",
    "x-auth-token", "x-access-token",
    "X-Token", "x-my-secret", "x-auth-pass",
])
def test_sensitive_header_names(name: str):
    assert _is_sensitive_header(name) is True


@pytest.mark.parametrize("name", [
    "X-Custom", "Accept", "Content-Type", "X-Request-ID", "User-Agent",
])
def test_non_sensitive_header_names(name: str):
    assert _is_sensitive_header(name) is False


def test_redact_sensitive_returns_placeholder():
    assert _redact("Authorization", "Bearer secret") == "<redacted>"


def test_redact_non_sensitive_returns_value():
    assert _redact("X-Custom", "my-value") == "my-value"


# ---------------------------------------------------------------------------
# SessionContext construction
# ---------------------------------------------------------------------------


def test_session_context_empty_by_default():
    ctx = SessionContext()
    assert ctx.is_empty
    assert ctx.header_count == 0
    assert ctx.cookie_count == 0
    assert not ctx.has_auth


def test_session_context_with_headers():
    ctx = SessionContext(headers={"X-My": "value"})
    assert ctx.header_count == 1
    assert not ctx.is_empty


def test_session_context_with_cookies():
    ctx = SessionContext(cookies={"sid": "abc"})
    assert ctx.cookie_count == 1
    assert not ctx.is_empty


def test_session_context_has_auth_via_bearer():
    ctx = SessionContext(_bearer_token="tok")
    assert ctx.has_auth


def test_session_context_has_auth_via_header():
    ctx = SessionContext(headers={"Authorization": "Bearer tok"})
    assert ctx.has_auth


def test_session_context_no_auth_without_token():
    ctx = SessionContext(headers={"X-Custom": "val"}, cookies={"s": "1"})
    assert not ctx.has_auth


# ---------------------------------------------------------------------------
# merged_headers / merged_cookies (internal use)
# ---------------------------------------------------------------------------


def test_merged_headers_includes_bearer_token():
    ctx = SessionContext(_bearer_token="mysecret")
    h = ctx.merged_headers()
    assert h["Authorization"] == "Bearer mysecret"


def test_merged_headers_includes_custom_headers():
    ctx = SessionContext(headers={"X-Foo": "bar"})
    h = ctx.merged_headers()
    assert h["X-Foo"] == "bar"
    assert "Authorization" not in h


def test_merged_cookies_returns_copy():
    ctx = SessionContext(cookies={"c": "v"})
    c1 = ctx.merged_cookies()
    c2 = ctx.merged_cookies()
    assert c1 == c2
    c1["extra"] = "x"
    assert "extra" not in ctx.merged_cookies()


# ---------------------------------------------------------------------------
# Safe representations — secrets must not leak
# ---------------------------------------------------------------------------


def test_repr_does_not_expose_token():
    ctx = SessionContext(_bearer_token="supersecret")
    r = repr(ctx)
    assert "supersecret" not in r
    assert "<set>" in r


def test_repr_shows_counts():
    ctx = SessionContext(headers={"A": "1", "B": "2"}, cookies={"c": "x"})
    r = repr(ctx)
    assert "headers=2" in r
    assert "cookies=1" in r


def test_to_dict_redacts_authorization():
    ctx = SessionContext(headers={"Authorization": "Bearer tok"})
    d = ctx.to_dict()
    assert d["headers"]["Authorization"] == "<redacted>"


def test_to_dict_redacts_all_cookies():
    ctx = SessionContext(cookies={"session": "abc", "csrf": "xyz"})
    d = ctx.to_dict()
    for v in d["cookies"].values():
        assert v == "<redacted>"


def test_to_dict_bearer_shown_as_set():
    ctx = SessionContext(_bearer_token="tok")
    assert ctx.to_dict()["bearer_token"] == "<set>"


def test_to_dict_bearer_none_when_not_set():
    ctx = SessionContext()
    assert ctx.to_dict()["bearer_token"] is None


def test_to_json_is_valid_json():
    ctx = SessionContext(headers={"X-A": "1"}, _bearer_token="tok")
    data = json.loads(ctx.to_json())
    assert "bearer_token" in data
    assert data["bearer_token"] == "<set>"


def test_to_json_does_not_expose_token():
    ctx = SessionContext(_bearer_token="topsecret")
    assert "topsecret" not in ctx.to_json()


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


def test_from_env_loads_token(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_TOKEN", "secret123")
    ctx = SessionContext.from_env("MY_TOKEN")
    assert ctx._bearer_token == "secret123"  # noqa: SLF001
    assert not ctx.is_empty


def test_from_env_raises_when_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("WEBHOUND_MISSING_VAR", raising=False)
    with pytest.raises(ValueError, match="not set or empty"):
        SessionContext.from_env("WEBHOUND_MISSING_VAR")


def test_from_env_raises_when_empty(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_TOKEN", "")
    with pytest.raises(ValueError, match="not set or empty"):
        SessionContext.from_env("MY_TOKEN")


# ---------------------------------------------------------------------------
# from_file
# ---------------------------------------------------------------------------


def test_from_file_loads_headers_and_cookies(tmp_path: Path):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({
        "headers": {"X-Custom": "value"},
        "cookies": {"sid": "abc"},
    }), encoding="utf-8")
    ctx = SessionContext.from_file(session_file)
    assert ctx.header_count == 1
    assert ctx.cookie_count == 1


def test_from_file_ignores_token_fields(tmp_path: Path):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({
        "headers": {},
        "cookies": {},
        "token": "shouldbeignored",
        "password": "alsoignored",
    }), encoding="utf-8")
    ctx = SessionContext.from_file(session_file)
    assert ctx._bearer_token is None  # noqa: SLF001


def test_from_file_invalid_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="valid JSON"):
        SessionContext.from_file(bad)


def test_from_file_not_object(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('["list"]', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        SessionContext.from_file(bad)


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------


def test_merge_later_headers_win():
    ctx1 = SessionContext(headers={"X-A": "first"})
    ctx2 = SessionContext(headers={"X-A": "second"})
    merged = SessionContext.merge(ctx1, ctx2)
    assert merged.merged_headers()["X-A"] == "second"


def test_merge_combines_cookies():
    ctx1 = SessionContext(cookies={"a": "1"})
    ctx2 = SessionContext(cookies={"b": "2"})
    merged = SessionContext.merge(ctx1, ctx2)
    c = merged.merged_cookies()
    assert c["a"] == "1"
    assert c["b"] == "2"


def test_merge_last_token_wins():
    ctx1 = SessionContext(_bearer_token="first")
    ctx2 = SessionContext(_bearer_token="second")
    merged = SessionContext.merge(ctx1, ctx2)
    assert merged._bearer_token == "second"  # noqa: SLF001


def test_merge_empty_contexts():
    merged = SessionContext.merge(SessionContext(), SessionContext())
    assert merged.is_empty


# ---------------------------------------------------------------------------
# SafeHttpClient — session headers sent with requests
# ---------------------------------------------------------------------------


class _RecordingTransport(httpx.AsyncBaseTransport):
    """Captures the last request so tests can inspect headers/cookies."""

    def __init__(self) -> None:
        self.last_request: httpx.Request | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.last_request = request
        return httpx.Response(200, text="ok")


@pytest.fixture()
def fast_options() -> ScanOptions:
    return ScanOptions(rate_limit_rps=10.0)


@pytest.mark.anyio
async def test_http_client_sends_session_header(fast_options: ScanOptions):
    transport = _RecordingTransport()
    ctx = SessionContext(headers={"X-Custom-Header": "test-value"})
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
        session_context=ctx,
    ) as client:
        await client.get("https://example.com/")
    assert transport.last_request is not None
    assert transport.last_request.headers.get("x-custom-header") == "test-value"


@pytest.mark.anyio
async def test_http_client_sends_bearer_token(fast_options: ScanOptions):
    transport = _RecordingTransport()
    ctx = SessionContext(_bearer_token="mytoken")
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
        session_context=ctx,
    ) as client:
        await client.get("https://example.com/")
    assert transport.last_request is not None
    auth = transport.last_request.headers.get("authorization")
    assert auth == "Bearer mytoken"


@pytest.mark.anyio
async def test_http_client_without_session_context_has_no_auth(fast_options: ScanOptions):
    transport = _RecordingTransport()
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        await client.get("https://example.com/")
    assert transport.last_request is not None
    assert "authorization" not in transport.last_request.headers


@pytest.mark.anyio
async def test_http_client_sends_session_cookies(fast_options: ScanOptions):
    transport = _RecordingTransport()
    ctx = SessionContext(cookies={"session_id": "abc123"})
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
        session_context=ctx,
    ) as client:
        await client.get("https://example.com/")
    assert transport.last_request is not None
    cookie_header = transport.last_request.headers.get("cookie", "")
    assert "session_id=abc123" in cookie_header


# ---------------------------------------------------------------------------
# Secrets must not appear in scan result metadata
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_session_secrets_not_in_scan_metadata(fast_options: ScanOptions):
    """Verify that bearer tokens never appear in HTTP fetch stats or result metadata."""
    transport = _RecordingTransport()
    ctx = SessionContext(_bearer_token="topsecretvalue")
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
        session_context=ctx,
    ) as client:
        await client.get("https://example.com/")
        stats = client.fetch_stats.to_dict()
    stats_json = json.dumps(stats)
    assert "topsecretvalue" not in stats_json


# ---------------------------------------------------------------------------
# POST / state-mutating methods are still unavailable
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_post_method_not_available(fast_options: ScanOptions):
    transport = _RecordingTransport()
    ctx = SessionContext(headers={"X-Session": "value"})
    async with SafeHttpClient(
        fast_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
        session_context=ctx,
    ) as client:
        assert not hasattr(client, "post")
        assert not hasattr(client, "put")
        assert not hasattr(client, "delete")
        assert not hasattr(client, "patch")
