# WebHound — webhound/browser/playwright_runner.py
# Phase-5A: opt-in Playwright runner that drives Chromium in
# headless mode, waits for hydration, and captures every network
# request the page fires.
#
# DEPENDENCY POSTURE:
#   * Playwright Python is imported lazily inside ``run_browser_pass``.
#     Environments that don't have it installed get a clean
#     ``BrowserPassResult(deferred=True, error=...)`` rather than an
#     import error at module load time.
#   * Operators must run ``playwright install chromium`` once before
#     the runner can actually launch a browser. The runner detects
#     missing browsers and returns a deferred result with a clear
#     ``error="chromium not installed"`` message instead of crashing.
#
# SAFE-MODE GUARANTEES (matching the scanner-wide contract):
#   * Form submission disabled — the runner only navigates.
#   * No interactive clicks beyond the configured low-risk affordances
#     (currently: scroll-to-bottom + wait for hydration).
#   * Per-page wall-clock timeout caps every navigation.
#   * Requests are observed, never modified; no header injection, no
#     request blocking.
#
# All real-browser tests are MOCKED at the runner boundary — see
# ``scanner/tests/test_browser_runner.py``. The Playwright import is
# only exercised when ``WEBHOUND_BROWSER_ENABLED=1`` AND a browser
# binary is present, neither of which is true in CI.

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlparse

from webhound.browser.models import (
    BrowserTelemetry,
    NetworkArtifact,
)

logger = logging.getLogger(__name__)


_DEFAULT_NAV_TIMEOUT_MS = 30_000
_DEFAULT_IDLE_WAIT_MS = 1_500
_DEFAULT_HYDRATION_WAIT_MS = 2_000


@dataclass
class BrowserPassResult:
    """Outcome of one ``run_browser_pass`` call.

    ``deferred=True`` means the runner declined to run (Playwright not
    installed, browser missing, ``allow_network=False``). ``error`` is
    populated with a human-readable explanation. ``deferred=False`` +
    ``error=None`` means the pass ran; ``telemetries`` will be
    populated even if individual pages errored (per-page errors land
    inside each ``BrowserTelemetry.errors``)."""

    telemetries: list[BrowserTelemetry] = field(default_factory=list)
    deferred: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Resource-type → high-level kind mapping. Playwright reports the
# raw resource type from Chromium; we collapse to the categories the
# rest of the scanner reasons about.
# ---------------------------------------------------------------------------


_RESOURCE_KIND = {
    "fetch":       "fetch",
    "xhr":         "xhr",
    "websocket":   "websocket",
    "eventsource": "eventsource",
    "script":      "script",
    "stylesheet":  "stylesheet",
    "image":       "image",
    "media":       "media",
    "font":        "font",
    "manifest":    "manifest",
    "document":    "navigation",
    "subdocument": "iframe",
    "preflight":   "fetch",
    "ping":        "beacon",
    "other":       "unknown",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_browser_pass(
    page_urls: list[str],
    *,
    allow_network: bool = False,
    per_page_timeout_ms: int = _DEFAULT_NAV_TIMEOUT_MS,
    hydration_wait_ms: int = _DEFAULT_HYDRATION_WAIT_MS,
    idle_wait_ms: int = _DEFAULT_IDLE_WAIT_MS,
    user_agent: str | None = None,
    runner: Callable[..., Awaitable["BrowserPassResult"]] | None = None,
) -> BrowserPassResult:
    """Visit every URL in ``page_urls`` in a headless Chromium
    context, capturing network artifacts.

    ``allow_network`` MUST be True for the runner to actually launch a
    browser — matching the scanner's safe-mode posture. Without it,
    returns ``deferred=True`` immediately.

    ``runner`` is an injection seam for tests: when supplied it
    replaces the Playwright execution path, so unit tests can return
    deterministic telemetry without installing browsers."""
    if not page_urls:
        return BrowserPassResult()
    if runner is not None:
        return await runner(
            page_urls,
            allow_network=allow_network,
            per_page_timeout_ms=per_page_timeout_ms,
            hydration_wait_ms=hydration_wait_ms,
            idle_wait_ms=idle_wait_ms,
            user_agent=user_agent,
        )
    if not allow_network:
        return BrowserPassResult(
            deferred=True,
            error="browser pass disabled: allow_network=False",
        )
    return await _playwright_pass(
        page_urls,
        per_page_timeout_ms=per_page_timeout_ms,
        hydration_wait_ms=hydration_wait_ms,
        idle_wait_ms=idle_wait_ms,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Real Playwright execution (lazy import + graceful degradation)
# ---------------------------------------------------------------------------


async def _playwright_pass(
    page_urls: list[str],
    *,
    per_page_timeout_ms: int,
    hydration_wait_ms: int,
    idle_wait_ms: int,
    user_agent: str | None,
) -> BrowserPassResult:
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        return BrowserPassResult(
            deferred=True,
            error="playwright not installed (pip install playwright)",
        )

    telemetries: list[BrowserTelemetry] = []
    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True)
            except Exception as exc:  # noqa: BLE001
                # Common case: "Executable doesn't exist at .../chrome"
                # means the operator hasn't run ``playwright install
                # chromium``. Surface a clear deferred result instead
                # of a stack trace.
                return BrowserPassResult(
                    deferred=True,
                    error=f"chromium launch failed: {exc}",
                )
            try:
                context = await browser.new_context(
                    user_agent=user_agent,
                    bypass_csp=False,
                    java_script_enabled=True,
                    ignore_https_errors=False,
                )
                # Per-page work — sequential because hammering a single
                # target with parallel pages would violate the
                # scanner's rate-limit posture.
                for url in page_urls:
                    page = await context.new_page()
                    tel = BrowserTelemetry(page_url=url)
                    _wire_capture(page, tel)
                    try:
                        await asyncio.wait_for(
                            page.goto(url, wait_until="domcontentloaded"),
                            timeout=per_page_timeout_ms / 1000.0,
                        )
                        # Hydration window — give SPA frameworks time
                        # to fire their first round of API calls.
                        await asyncio.sleep(hydration_wait_ms / 1000.0)
                        try:
                            await page.wait_for_load_state(
                                "networkidle",
                                timeout=idle_wait_ms,
                            )
                        except Exception:  # noqa: BLE001
                            pass
                        tel.final_url = page.url
                    except asyncio.TimeoutError:
                        tel.errors.append(
                            f"navigation timeout after {per_page_timeout_ms}ms"
                        )
                    except Exception as exc:  # noqa: BLE001
                        tel.errors.append(
                            f"{type(exc).__name__}: {exc}"
                        )
                    finally:
                        tel.finished_at = datetime.now(timezone.utc)
                        await page.close()
                    telemetries.append(tel)
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001
        return BrowserPassResult(
            telemetries=telemetries,
            error=f"playwright pass failed: {exc}",
        )
    return BrowserPassResult(telemetries=telemetries)


def _wire_capture(page, tel: BrowserTelemetry) -> None:
    """Subscribe to the Playwright Page events that produce
    NetworkArtifact entries. Each handler is defensive — a bad event
    payload must never abort the navigation."""

    def _on_request(req) -> None:
        try:
            kind = _RESOURCE_KIND.get(
                (req.resource_type or "other").lower(), "unknown",
            )
            tel.add(NetworkArtifact(
                url=req.url, method=req.method,
                initiator_kind=kind,
                page_url=tel.page_url,
                request_started_at=datetime.now(timezone.utc),
            ))
        except Exception:  # noqa: BLE001
            pass

    def _on_response(resp) -> None:
        try:
            # Find the matching pending artifact (last-with-no-status
            # for the same URL) and fill in the response fields.
            for art in reversed(tel.artifacts):
                if art.url == resp.url and art.status_code is None:
                    art.status_code = resp.status
                    art.content_type = (
                        resp.headers.get("content-type") if resp.headers
                        else None
                    )
                    break
        except Exception:  # noqa: BLE001
            pass

    def _on_websocket(ws) -> None:
        try:
            tel.add(NetworkArtifact(
                url=ws.url, method="GET",
                initiator_kind="websocket",
                page_url=tel.page_url,
                request_started_at=datetime.now(timezone.utc),
            ))
        except Exception:  # noqa: BLE001
            pass

    def _on_frame_attached(frame) -> None:
        try:
            if frame.url and frame.url != tel.page_url:
                tel.add(NetworkArtifact(
                    url=frame.url, method="GET",
                    initiator_kind="iframe",
                    page_url=tel.page_url,
                ))
        except Exception:  # noqa: BLE001
            pass

    page.on("request", _on_request)
    page.on("response", _on_response)
    page.on("websocket", _on_websocket)
    page.on("frameattached", _on_frame_attached)


# ---------------------------------------------------------------------------
# Convenience: env-driven helper used by the orchestrator
# ---------------------------------------------------------------------------


def browser_pass_enabled() -> bool:
    return os.getenv("WEBHOUND_BROWSER_ENABLED", "0") == "1"
