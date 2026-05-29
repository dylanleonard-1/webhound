# WebHound — webhound/browser/__init__.py
# Phase-5A: Playwright-backed browser execution + network capture.
#
# The browser pass is opt-in (ScanOptions.browser_enabled, set on the
# ENTERPRISE profile and any custom profile that wants SPA visibility).
# Default scans still use the static crawler — no behavioural change,
# no Playwright dependency required, no Chromium download.
#
# The runner module imports Playwright lazily inside the entry point
# so the rest of the scanner package keeps importing on environments
# that don't have it installed.
