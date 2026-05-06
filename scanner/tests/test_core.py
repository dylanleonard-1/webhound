# WebHound — scanner/tests/test_core.py
# Pytest tests for Phase 2A: http_client, scope, and scan_context.

from __future__ import annotations

import httpx
import pytest

from webhound.core.http_client import WEBHOUND_USER_AGENT, HttpResponse, SafeHttpClient
from webhound.core.scan_context import QueueItem, ScanContext
from webhound.core.scope import ScopeChecker, UrlNormalizer
from webhound.models.target import ScanOptions, Target, TargetScope


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _target(url: str = "https://example.com", **kw) -> Target:
    return Target.from_url(url, **kw)


def _target_with_opts(**opts) -> Target:
    return Target.from_url("https://example.com", scan_options=ScanOptions(**opts))


def _mock_transport(status: int = 200, body: str = "<html></html>", headers: dict | None = None) -> httpx.MockTransport:
    """Return an httpx MockTransport that replies with a fixed response."""
    _headers = {"content-type": "text/html; charset=utf-8"}
    if headers:
        _headers.update(headers)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=status, text=body, headers=_headers)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# UrlNormalizer tests
# ---------------------------------------------------------------------------


class TestUrlNormalizer:
    def test_strips_fragment(self):
        assert UrlNormalizer.normalize("https://example.com/page#section") == "https://example.com/page"

    def test_lowercase_scheme(self):
        assert UrlNormalizer.normalize("HTTPS://Example.COM/") == "https://example.com/"

    def test_lowercase_hostname(self):
        n = UrlNormalizer.normalize("https://EXAMPLE.COM/path")
        assert n and "example.com" in n

    def test_strips_default_http_port(self):
        assert UrlNormalizer.normalize("http://example.com:80/") == "http://example.com/"

    def test_strips_default_https_port(self):
        assert UrlNormalizer.normalize("https://example.com:443/") == "https://example.com/"

    def test_keeps_non_default_port(self):
        n = UrlNormalizer.normalize("https://example.com:8443/")
        assert n == "https://example.com:8443/"

    def test_empty_path_becomes_slash(self):
        assert UrlNormalizer.normalize("https://example.com") == "https://example.com/"

    def test_collapses_double_slashes(self):
        n = UrlNormalizer.normalize("https://example.com//path//page")
        assert n == "https://example.com/path/page"

    def test_preserves_query_string(self):
        n = UrlNormalizer.normalize("https://example.com/search?q=test&page=1")
        assert n and "q=test" in n

    def test_rejects_javascript_scheme(self):
        assert UrlNormalizer.normalize("javascript:alert(1)") is None

    def test_rejects_mailto(self):
        assert UrlNormalizer.normalize("mailto:user@example.com") is None

    def test_rejects_data_uri(self):
        assert UrlNormalizer.normalize("data:text/plain,hello") is None

    def test_rejects_ftp(self):
        assert UrlNormalizer.normalize("ftp://files.example.com/") is None

    def test_rejects_empty_string(self):
        assert UrlNormalizer.normalize("") is None

    def test_rejects_fragment_only(self):
        assert UrlNormalizer.normalize("#anchor") is None

    def test_resolves_relative_url(self):
        n = UrlNormalizer.normalize("/about", base_url="https://example.com/blog/")
        assert n == "https://example.com/about"

    def test_resolves_relative_subpath(self):
        n = UrlNormalizer.normalize("page2", base_url="https://example.com/blog/")
        assert n == "https://example.com/blog/page2"

    def test_absolute_url_ignores_base(self):
        n = UrlNormalizer.normalize("https://other.com/", base_url="https://example.com/")
        assert n == "https://other.com/"

    def test_path_segments(self):
        assert UrlNormalizer.path_segments("https://example.com/blog/post/1") == ["blog", "post", "1"]

    def test_path_segments_root(self):
        assert UrlNormalizer.path_segments("https://example.com/") == []


# ---------------------------------------------------------------------------
# ScopeChecker tests — FULL_DOMAIN (default)
# ---------------------------------------------------------------------------


class TestScopeCheckerFullDomain:
    def test_same_domain_in_scope(self):
        sc = ScopeChecker(_target())
        assert sc.is_in_scope("https://example.com/page")

    def test_same_domain_different_path_in_scope(self):
        sc = ScopeChecker(_target())
        assert sc.is_in_scope("https://example.com/blog/post/123")

    def test_external_domain_blocked(self):
        sc = ScopeChecker(_target())
        assert not sc.is_in_scope("https://evil.com/attack")

    def test_external_domain_reason(self):
        sc = ScopeChecker(_target())
        reason = sc.out_of_scope_reason("https://evil.com/")
        assert reason and "evil.com" in reason

    def test_similar_domain_blocked(self):
        sc = ScopeChecker(_target())
        assert not sc.is_in_scope("https://example.com.evil.net/")

    def test_subdomain_blocked_by_default(self):
        sc = ScopeChecker(_target())
        assert not sc.is_in_scope("https://sub.example.com/page")

    def test_subdomain_allowed_when_option_set(self):
        t = _target_with_opts(include_subdomains=True)
        sc = ScopeChecker(t)
        assert sc.is_in_scope("https://sub.example.com/page")

    def test_deep_subdomain_allowed_when_option_set(self):
        t = _target_with_opts(include_subdomains=True)
        sc = ScopeChecker(t)
        assert sc.is_in_scope("https://api.v2.example.com/data")

    def test_javascript_scheme_out_of_scope(self):
        sc = ScopeChecker(_target())
        assert not sc.is_in_scope("javascript:void(0)")

    def test_mailto_out_of_scope(self):
        sc = ScopeChecker(_target())
        assert not sc.is_in_scope("mailto:admin@example.com")

    def test_in_scope_returns_none_reason(self):
        sc = ScopeChecker(_target())
        assert sc.out_of_scope_reason("https://example.com/") is None

    def test_is_valid_url(self):
        sc = ScopeChecker(_target())
        assert sc.is_valid_url("https://example.com/")
        assert not sc.is_valid_url("not-a-url")
        assert not sc.is_valid_url("ftp://example.com/")


# ---------------------------------------------------------------------------
# ScopeChecker — SINGLE_PAGE scope
# ---------------------------------------------------------------------------


class TestScopeCheckerSinglePage:
    def test_root_url_in_scope(self):
        t = Target.from_url("https://example.com/landing", scope=TargetScope.SINGLE_PAGE)
        sc = ScopeChecker(t)
        assert sc.is_in_scope("https://example.com/landing")

    def test_other_path_blocked(self):
        t = Target.from_url("https://example.com/landing", scope=TargetScope.SINGLE_PAGE)
        sc = ScopeChecker(t)
        assert not sc.is_in_scope("https://example.com/other")

    def test_reason_mentions_single_page(self):
        t = Target.from_url("https://example.com/landing", scope=TargetScope.SINGLE_PAGE)
        sc = ScopeChecker(t)
        reason = sc.out_of_scope_reason("https://example.com/other")
        assert reason and "SINGLE_PAGE" in reason


# ---------------------------------------------------------------------------
# ScopeChecker — SUBDIRECTORY scope
# ---------------------------------------------------------------------------


class TestScopeCheckerSubdirectory:
    def test_child_path_in_scope(self):
        t = Target.from_url("https://example.com/blog/", scope=TargetScope.SUBDIRECTORY)
        sc = ScopeChecker(t)
        assert sc.is_in_scope("https://example.com/blog/post/1")

    def test_sibling_path_blocked(self):
        t = Target.from_url("https://example.com/blog/", scope=TargetScope.SUBDIRECTORY)
        sc = ScopeChecker(t)
        assert not sc.is_in_scope("https://example.com/about")

    def test_root_path_blocked(self):
        t = Target.from_url("https://example.com/blog/", scope=TargetScope.SUBDIRECTORY)
        sc = ScopeChecker(t)
        assert not sc.is_in_scope("https://example.com/")


# ---------------------------------------------------------------------------
# ScopeChecker — URL_LIST scope
# ---------------------------------------------------------------------------


class TestScopeCheckerUrlList:
    def test_listed_url_in_scope(self):
        t = Target.from_url(
            "https://example.com",
            scope=TargetScope.URL_LIST,
            scope_urls=["https://example.com/page1", "https://example.com/page2"],
        )
        sc = ScopeChecker(t)
        assert sc.is_in_scope("https://example.com/page1")

    def test_unlisted_url_blocked(self):
        t = Target.from_url(
            "https://example.com",
            scope=TargetScope.URL_LIST,
            scope_urls=["https://example.com/page1"],
        )
        sc = ScopeChecker(t)
        assert not sc.is_in_scope("https://example.com/page2")

    def test_empty_list_blocks_all(self):
        t = Target.from_url("https://example.com", scope=TargetScope.URL_LIST, scope_urls=[])
        sc = ScopeChecker(t)
        assert not sc.is_in_scope("https://example.com/")


# ---------------------------------------------------------------------------
# SafeHttpClient tests (async — uses MockTransport, no real network)
# ---------------------------------------------------------------------------


class TestSafeHttpClient:
    @pytest.mark.anyio
    async def test_user_agent_present_in_options(self):
        opts = ScanOptions()
        client = SafeHttpClient(opts)
        assert "WebHound" in client.user_agent

    @pytest.mark.anyio
    async def test_default_user_agent_contains_webhound(self):
        async with SafeHttpClient() as client:
            assert "WebHound" in client.user_agent

    @pytest.mark.anyio
    async def test_timeout_configuration(self):
        opts = ScanOptions(request_timeout_seconds=45)
        client = SafeHttpClient(opts)
        assert client.timeout_seconds == 45

    @pytest.mark.anyio
    async def test_rate_limit_configuration(self):
        opts = ScanOptions(rate_limit_rps=1.0)
        client = SafeHttpClient(opts)
        assert client.rate_limit_rps == 1.0

    @pytest.mark.anyio
    async def test_get_returns_response(self):
        transport = _mock_transport(200, "<html><body>hello</body></html>")
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.status_code == 200
        assert "hello" in resp.body

    @pytest.mark.anyio
    async def test_response_has_request_id(self):
        transport = _mock_transport()
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.request_id is not None

    @pytest.mark.anyio
    async def test_response_records_original_url(self):
        transport = _mock_transport()
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/path")
        assert resp.original_url == "https://example.com/path"

    @pytest.mark.anyio
    async def test_response_has_elapsed_ms(self):
        transport = _mock_transport()
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert isinstance(resp.elapsed_ms, float)
        assert resp.elapsed_ms >= 0.0

    @pytest.mark.anyio
    async def test_response_headers_lowercase(self):
        transport = _mock_transport(headers={"X-Custom-Header": "value"})
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.header("content-type") is not None
        assert resp.header("x-custom-header") == "value"

    @pytest.mark.anyio
    async def test_is_success_true_for_200(self):
        transport = _mock_transport(200)
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.is_success

    @pytest.mark.anyio
    async def test_is_success_false_for_404(self):
        transport = _mock_transport(404)
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/missing")
        assert not resp.is_success
        assert resp.is_client_error

    @pytest.mark.anyio
    async def test_is_server_error_for_500(self):
        transport = _mock_transport(500)
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.is_server_error

    @pytest.mark.anyio
    async def test_head_request(self):
        transport = _mock_transport(200)
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.head("https://example.com/")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_captured_at_is_utc(self):
        from datetime import timezone as tz
        transport = _mock_transport()
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.captured_at.tzinfo == tz.utc

    @pytest.mark.anyio
    async def test_failed_response_on_connect_error(self):
        async def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        transport = httpx.MockTransport(error_handler)
        async with SafeHttpClient(transport=transport) as client:
            resp = await client.get("https://example.com/")
        assert resp.failed
        assert resp.status_code == 0
        assert resp.error is not None

    @pytest.mark.anyio
    async def test_webhound_constant_matches_default_user_agent(self):
        opts = ScanOptions()
        assert WEBHOUND_USER_AGENT in opts.user_agent


# ---------------------------------------------------------------------------
# ScanContext tests
# ---------------------------------------------------------------------------


class TestScanContext:
    def test_initial_pages_crawled_zero(self):
        ctx = ScanContext(_target())
        assert ctx.pages_crawled == 0

    def test_max_pages_from_options(self):
        t = _target_with_opts(max_pages=50)
        ctx = ScanContext(t)
        assert ctx.max_pages == 50

    def test_max_depth_from_options(self):
        t = _target_with_opts(max_depth=4)
        ctx = ScanContext(t)
        assert ctx.max_depth == 4

    def test_pages_remaining_initially_equals_max(self):
        t = _target_with_opts(max_pages=10)
        ctx = ScanContext(t)
        assert ctx.pages_remaining == 10

    def test_can_crawl_in_scope_url(self):
        ctx = ScanContext(_target())
        assert ctx.can_crawl("https://example.com/page", depth=1)

    def test_cannot_crawl_external_url(self):
        ctx = ScanContext(_target())
        assert not ctx.can_crawl("https://evil.com/page", depth=1)

    def test_cannot_crawl_visited_url(self):
        ctx = ScanContext(_target())
        ctx.mark_visited("https://example.com/page", depth=1)
        assert not ctx.can_crawl("https://example.com/page", depth=1)

    def test_cannot_crawl_beyond_max_depth(self):
        t = _target_with_opts(max_depth=2)
        ctx = ScanContext(t)
        assert not ctx.can_crawl("https://example.com/a/b/c", depth=3)

    def test_cannot_crawl_when_budget_exhausted(self):
        t = _target_with_opts(max_pages=1)
        ctx = ScanContext(t)
        ctx.mark_visited("https://example.com/", depth=0)
        assert ctx.is_budget_exhausted
        assert not ctx.can_crawl("https://example.com/page2", depth=1)

    def test_mark_visited_increments_count(self):
        ctx = ScanContext(_target())
        ctx.mark_visited("https://example.com/", depth=0)
        assert ctx.pages_crawled == 1
        assert ctx.pages_remaining == ctx.max_pages - 1

    def test_is_visited_true_after_mark(self):
        ctx = ScanContext(_target())
        ctx.mark_visited("https://example.com/page")
        assert ctx.is_visited("https://example.com/page")

    def test_is_visited_false_before_mark(self):
        ctx = ScanContext(_target())
        assert not ctx.is_visited("https://example.com/unseen")

    def test_enqueue_adds_to_queue(self):
        ctx = ScanContext(_target())
        added = ctx.enqueue("https://example.com/page", depth=1)
        assert added
        assert ctx.queue_size == 1

    def test_enqueue_rejects_out_of_scope(self):
        ctx = ScanContext(_target())
        added = ctx.enqueue("https://evil.com/", depth=1)
        assert not added
        assert ctx.queue_size == 0

    def test_enqueue_no_duplicate(self):
        ctx = ScanContext(_target())
        ctx.enqueue("https://example.com/page", depth=1)
        ctx.enqueue("https://example.com/page", depth=1)
        assert ctx.queue_size == 1

    def test_dequeue_returns_item(self):
        ctx = ScanContext(_target())
        ctx.enqueue("https://example.com/page", depth=1)
        item = ctx.dequeue()
        assert item is not None
        assert item.depth == 1
        assert "example.com" in item.url

    def test_dequeue_empty_returns_none(self):
        ctx = ScanContext(_target())
        assert ctx.dequeue() is None

    def test_seed_adds_root(self):
        ctx = ScanContext(_target())
        ctx.seed("https://example.com/")
        assert ctx.queue_size == 1

    def test_record_error_adds_to_result(self):
        ctx = ScanContext(_target())
        ctx.record_error("headers_engine", "connection refused", "https://example.com/")
        assert len(ctx.scan_result.errors) == 1

    def test_snapshot_structure(self):
        ctx = ScanContext(_target())
        snap = ctx.snapshot()
        assert "pages_crawled" in snap
        assert "pages_remaining" in snap
        assert "queue_size" in snap
        assert "budget_exhausted" in snap

    def test_finish_marks_complete(self):
        ctx = ScanContext(_target())
        ctx.mark_visited("https://example.com/", depth=0)
        result = ctx.finish()
        from webhound.models.scan_result import ScanStatus
        assert result.status == ScanStatus.COMPLETED
        assert result.urls_crawled == 1

    def test_has_work_false_when_queue_empty(self):
        ctx = ScanContext(_target())
        assert not ctx.has_work

    def test_has_work_true_after_enqueue(self):
        ctx = ScanContext(_target())
        ctx.enqueue("https://example.com/page", depth=1)
        assert ctx.has_work

    def test_depth_of_returns_crawl_depth(self):
        ctx = ScanContext(_target())
        ctx.mark_visited("https://example.com/page", depth=2)
        assert ctx.depth_of("https://example.com/page") == 2

    def test_depth_of_unknown_url_returns_none(self):
        ctx = ScanContext(_target())
        assert ctx.depth_of("https://example.com/unseen") is None
