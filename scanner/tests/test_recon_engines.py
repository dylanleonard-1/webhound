# WebHound — scanner/tests/test_recon_engines.py
# Tests for Phase 7 recon engines: SensitivePathsEngine and RobotsAndSitemapEngine.

from __future__ import annotations

import httpx
import pytest

from webhound.core.http_client import SafeHttpClient
from webhound.core.scope import ScopeChecker
from webhound.engines.recon.robots_sitemap import RobotsAndSitemapEngine
from webhound.engines.recon.sensitive_paths import SensitivePathsEngine
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target, TargetScope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _target(url: str = "https://example.com", scope: TargetScope = TargetScope.FULL_DOMAIN) -> Target:
    return Target.from_url(url, scope=scope)


def _route_transport(
    routes: dict[str, tuple[int, str, dict[str, str] | None]],
) -> httpx.MockTransport:
    """Mock transport routing by URL path → (status, body, extra_headers)."""
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in routes:
            status, body, extra = routes[path]
            h: dict[str, str] = {"content-type": "text/plain; charset=utf-8"}
            if extra:
                h.update(extra)
            return httpx.Response(status, text=body, headers=h)
        return httpx.Response(404, text="Not Found", headers={"content-type": "text/html"})
    return httpx.MockTransport(handler)


def _all_evidence_content(findings) -> str:
    return " ".join(ev.content for f in findings for ev in f.evidence)


# ---------------------------------------------------------------------------
# SensitivePathsEngine
# ---------------------------------------------------------------------------


class TestSensitivePathsEngine:

    @pytest.mark.anyio
    async def test_engine_name(self):
        assert SensitivePathsEngine.NAME == "sensitive_paths"

    @pytest.mark.anyio
    async def test_clean_target_no_findings(self):
        transport = _route_transport({})  # all paths → 404
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert findings == []

    @pytest.mark.anyio
    async def test_env_file_exposed_critical(self):
        transport = _route_transport({
            "/.env": (200, "DB_PASSWORD=mysecret\nAPP_KEY=base64:xxx\n", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("env" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_env_file_secrets_masked_in_evidence(self):
        secret = "superSECRETvalue123!@#"
        transport = _route_transport({
            "/.env": (200, f"DB_PASSWORD={secret}\nAPI_KEY=another_secret\n", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        evidence_text = _all_evidence_content(findings)
        assert secret not in evidence_text
        assert "another_secret" not in evidence_text
        assert "DB_PASSWORD=***" in evidence_text or "***" in evidence_text

    @pytest.mark.anyio
    async def test_wp_config_secrets_masked(self):
        body = (
            "<?php\n"
            "define('DB_PASSWORD', 'hunter2');\n"
            "define('AUTH_KEY', 'very-secret-auth-key');\n"
            "define('DB_NAME', 'wordpress');\n"
        )
        transport = _route_transport({
            "/wp-config.php": (200, body, {"content-type": "application/x-httpd-php"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert findings, "wp-config.php should be reported as exposed"
        evidence_text = _all_evidence_content(findings)
        assert "hunter2" not in evidence_text
        assert "very-secret-auth-key" not in evidence_text
        assert "DB_NAME" in evidence_text or "wordpress" in evidence_text or "***" in evidence_text

    @pytest.mark.anyio
    async def test_git_config_exposed_critical(self):
        body = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        transport = _route_transport({
            "/.git/config": (200, body, None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("git" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_backup_zip_exposed_high(self):
        transport = _route_transport({
            "/backup.zip": (200, "", {"content-type": "application/zip"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("backup" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_sql_backup_exposed_high(self):
        body = "-- MySQL dump 10.13\nCREATE TABLE users (\n  id INT\n);\nINSERT INTO users VALUES (1);\n"
        transport = _route_transport({
            "/backup.sql": (200, body, None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.HIGH for f in findings)

    @pytest.mark.anyio
    async def test_phpinfo_exposed_medium(self):
        body = "<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.0</body></html>"
        transport = _route_transport({
            "/phpinfo.php": (200, body, {"content-type": "text/html; charset=utf-8"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.MEDIUM for f in findings)
        assert any("phpinfo" in f.title.lower() or "php" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_wp_config_exposed_critical(self):
        body = "<?php\ndefine('DB_PASSWORD', 'dbpass123');\ndefine('DB_HOST', 'localhost');\n"
        transport = _route_transport({
            "/wp-config.php": (200, body, {"content-type": "application/x-httpd-php"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    @pytest.mark.anyio
    async def test_admin_path_accessible_medium(self):
        transport = _route_transport({
            "/admin": (200, "<html><title>Admin Panel</title></html>", {"content-type": "text/html"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any(f.severity == Severity.MEDIUM for f in findings)
        assert any("admin" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_404_not_reported(self):
        transport = _route_transport({
            "/.env": (404, "Not Found", None),
            "/.git/config": (404, "Not Found", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert findings == []

    @pytest.mark.anyio
    async def test_403_on_env_reported_as_info_heuristic(self):
        """Phase-1 accuracy fix: 403-only is now a weak status-only signal.
        The engine surfaces it for analyst awareness (when the baseline
        calibration probes don't show a catch-all 403) but at INFO + low
        confidence + 'heuristic' tag — not LOW. Tests `/.env` HIGH+ severity
        path passes the severity gate but lands in the heuristic bucket."""
        transport = _route_transport({
            "/.env": (403, "Forbidden", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert findings, "expected one heuristic 403-only finding for /.env"
        env_findings = [f for f in findings if "/.env" in (f.metadata.get("url") or "")]
        assert env_findings, "expected a finding scoped to /.env"
        f = env_findings[0]
        assert f.severity == Severity.INFO
        assert f.confidence < 0.5
        assert "heuristic" in (f.tags or [])
        assert f.quality_label in ("informational", "advisory")

    @pytest.mark.anyio
    async def test_scope_enforcement_single_page(self):
        transport = _route_transport({
            "/.env": (200, "DB_PASSWORD=secret\n", None),
        })
        # SINGLE_PAGE scope: only the root URL is in scope
        target = _target(scope=TargetScope.SINGLE_PAGE)
        scope = ScopeChecker(target)
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client, scope=scope)
        # /.env should be out of scope for SINGLE_PAGE
        env_findings = [f for f in findings if "env" in f.title.lower()]
        assert env_findings == []

    @pytest.mark.anyio
    async def test_finding_has_required_fields(self):
        transport = _route_transport({
            "/.env": (200, "APP_KEY=secret\nDB_PASSWORD=pass\n", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert findings
        f = next(f for f in findings if "env" in f.title.lower())
        assert f.severity == Severity.CRITICAL
        assert f.category.value == "recon"
        assert len(f.evidence) >= 1
        assert f.confidence > 0
        assert f.framework.owasp_top10
        assert f.framework.cwe_ids
        assert f.remediation
        assert "url" in f.metadata

    @pytest.mark.anyio
    async def test_debug_path_exposed(self):
        transport = _route_transport({
            "/debug": (200, "Debug mode active", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert any("debug" in f.title.lower() for f in findings)

    @pytest.mark.anyio
    async def test_no_finding_when_body_has_no_sql_indicators(self):
        # /backup.sql returns 200 but body has no SQL indicators
        transport = _route_transport({
            "/backup.sql": (200, "Nothing to see here", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        # SQL dump paths require body indicators
        sql_findings = [f for f in findings if "backup.sql" in str(f.metadata.get("path", ""))]
        assert sql_findings == []

    @pytest.mark.anyio
    async def test_multiple_paths_multiple_findings(self):
        transport = _route_transport({
            "/.env": (200, "DB_PASSWORD=x\n", None),
            "/admin": (200, "<html>Admin</html>", {"content-type": "text/html"}),
            "/phpinfo.php": (200, "<title>phpinfo()</title>PHP Version 8.0", {"content-type": "text/html"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await SensitivePathsEngine().probe(target, client)
        assert len(findings) >= 3


# ---------------------------------------------------------------------------
# RobotsAndSitemapEngine
# ---------------------------------------------------------------------------


_ROBOTS_WITH_SENSITIVE = """\
User-agent: *
Disallow: /admin/
Disallow: /wp-admin/
Disallow: /staging/
Allow: /public/

Sitemap: https://example.com/sitemap.xml
"""

_SITEMAP_WITH_SENSITIVE = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/admin/dashboard</loc></url>
  <url><loc>https://example.com/contact</loc></url>
  <url><loc>https://example.com/staging/test-page</loc></url>
</urlset>
"""

_SITEMAP_CLEAN = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/contact</loc></url>
</urlset>
"""

_SITEMAP_NO_NS = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/internal/config</loc></url>
</urlset>
"""


class TestRobotsAndSitemapEngine:

    @pytest.mark.anyio
    async def test_engine_name(self):
        assert RobotsAndSitemapEngine.NAME == "robots_sitemap"

    @pytest.mark.anyio
    async def test_no_robots_txt_info_finding(self):
        transport = _route_transport({})  # /robots.txt → 404
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        assert any("no robots.txt" in f.title.lower() for f in findings)
        assert all(f.severity == Severity.INFO for f in findings)

    @pytest.mark.anyio
    async def test_sensitive_admin_disallow_detected(self):
        transport = _route_transport({
            "/robots.txt": (200, _ROBOTS_WITH_SENSITIVE, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        disallow_findings = [f for f in findings if "sensitive" in f.title.lower()]
        assert len(disallow_findings) >= 1
        paths = [f.metadata.get("path", "") for f in disallow_findings]
        assert any("admin" in p for p in paths)

    @pytest.mark.anyio
    async def test_sensitive_staging_disallow_detected(self):
        transport = _route_transport({
            "/robots.txt": (200, _ROBOTS_WITH_SENSITIVE, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        disallow_findings = [f for f in findings if "sensitive" in f.title.lower()]
        paths = [f.metadata.get("path", "") for f in disallow_findings]
        assert any("staging" in p for p in paths)

    @pytest.mark.anyio
    async def test_benign_disallow_no_sensitive_finding(self):
        benign = "User-agent: *\nDisallow: /search\nDisallow: /cgi-bin\nAllow: /\n"
        transport = _route_transport({
            "/robots.txt": (200, benign, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        disallow_findings = [f for f in findings if "sensitive" in f.title.lower()]
        assert disallow_findings == []

    @pytest.mark.anyio
    async def test_sitemap_sensitive_url_detected(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow:\n", None),
            "/sitemap.xml": (200, _SITEMAP_WITH_SENSITIVE, {"content-type": "application/xml"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        sitemap_findings = [f for f in findings if "sitemap" in f.title.lower()]
        assert len(sitemap_findings) >= 1

    @pytest.mark.anyio
    async def test_clean_sitemap_no_finding(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow:\n", None),
            "/sitemap.xml": (200, _SITEMAP_CLEAN, {"content-type": "application/xml"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        sitemap_findings = [f for f in findings if "sitemap" in f.title.lower()]
        assert sitemap_findings == []

    @pytest.mark.anyio
    async def test_sitemap_url_in_robots_fetched(self):
        robots = "User-agent: *\nDisallow:\nSitemap: https://example.com/custom-sitemap.xml\n"
        transport = _route_transport({
            "/robots.txt": (200, robots, None),
            "/custom-sitemap.xml": (200, _SITEMAP_WITH_SENSITIVE, {"content-type": "application/xml"}),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        sitemap_findings = [f for f in findings if "sitemap" in f.title.lower()]
        assert len(sitemap_findings) >= 1

    @pytest.mark.anyio
    async def test_malformed_robots_txt_low_finding(self):
        malformed = "<html><body>404 Not Found</body></html>"
        transport = _route_transport({
            "/robots.txt": (200, malformed, {"content-type": "text/html"}),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        malformed_findings = [f for f in findings if "doesn't look like a valid" in f.title.lower()]
        assert len(malformed_findings) >= 1
        assert all(f.severity in (Severity.LOW, Severity.INFO) for f in malformed_findings)

    @pytest.mark.anyio
    async def test_sitemap_without_namespace(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow:\n", None),
            "/sitemap.xml": (200, _SITEMAP_NO_NS, {"content-type": "application/xml"}),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        sitemap_findings = [f for f in findings if "sitemap" in f.title.lower()]
        assert len(sitemap_findings) >= 1

    @pytest.mark.anyio
    async def test_finding_has_framework_alignment(self):
        transport = _route_transport({
            "/robots.txt": (200, _ROBOTS_WITH_SENSITIVE, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        sensitive_findings = [f for f in findings if f.severity != Severity.INFO]
        assert sensitive_findings
        for f in sensitive_findings:
            assert f.framework.owasp_top10
            assert f.framework.cwe_ids
            assert f.scanner_engine == "robots_sitemap"

    @pytest.mark.anyio
    async def test_disallow_finding_severity_is_low(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow: /admin/\n", None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        disallow_findings = [f for f in findings if "sensitive" in f.title.lower()]
        assert all(f.severity == Severity.LOW for f in disallow_findings)

    @pytest.mark.anyio
    async def test_wp_admin_disallow_detected(self):
        robots = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\n"
        transport = _route_transport({
            "/robots.txt": (200, robots, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        paths = [f.metadata.get("path", "") for f in findings]
        assert any("wp-admin" in p for p in paths)

    @pytest.mark.anyio
    async def test_no_duplicate_disallow_findings(self):
        # Same path appears twice in robots.txt
        robots = "User-agent: *\nDisallow: /admin/\n\nUser-agent: Googlebot\nDisallow: /admin/\n"
        transport = _route_transport({
            "/robots.txt": (200, robots, None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        admin_findings = [f for f in findings if f.metadata.get("path") == "/admin/"]
        assert len(admin_findings) == 1

    @pytest.mark.anyio
    async def test_sitemap_missing_no_error(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow:\n", None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        # No error, just no sitemap findings
        assert isinstance(findings, list)

    @pytest.mark.anyio
    async def test_evidence_has_location(self):
        transport = _route_transport({
            "/robots.txt": (200, "User-agent: *\nDisallow: /admin/\n", None),
            "/sitemap.xml": (404, "", None),
        })
        target = _target()
        async with SafeHttpClient(transport=transport) as client:
            findings = await RobotsAndSitemapEngine().analyze(target, client)
        for f in findings:
            for ev in f.evidence:
                assert ev.location
                assert ev.source_engine == "robots_sitemap"
