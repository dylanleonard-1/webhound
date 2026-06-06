# WebHound — webhound/browser/script_collector.py
# Phase-6B: rendered-script collection. SPAs attach most of their
# JavaScript after hydration (dynamic chunks, module preloads,
# runtime-injected tags), so the static crawler's <script> view is
# incomplete by design. This module walks the *live* DOM read-only
# and records every script reference the page ended up with, plus
# any service-worker registration visible to the page.
#
# Inline bodies are never stored whole — a bounded snippet + sha256
# of that snippet is kept so WADE/baselines can diff scripts without
# the scan output carrying megabytes of bundle text.

from __future__ import annotations

import logging

from webhound.browser.models import BrowserTelemetry, RenderedScript
from webhound.utils.hashing import sha256_hex

logger = logging.getLogger(__name__)

_MAX_SCRIPTS = 500
_SNIPPET_CAP = 400

SCRIPT_WALK_JS = """
() => {
  const out = { scripts: [], hints: [] };
  for (const s of document.querySelectorAll('script')) {
    if (out.scripts.length >= %(max)d) break;
    try {
      const rawSrc = s.getAttribute('src');
      let src = null;
      try {
        src = rawSrc ? new URL(rawSrc, document.baseURI).href : null;
      } catch (e) {}
      const type = (s.getAttribute('type') || '').toLowerCase();
      const text = src ? '' : (s.textContent || '');
      out.scripts.push({
        src: src,
        module: type === 'module',
        snippet: text.slice(0, %(cap)d),
        textLength: text.length,
      });
    } catch (e) {}
  }
  const rels = 'link[rel="preload"], link[rel="prefetch"], link[rel="modulepreload"]';
  for (const l of document.querySelectorAll(rels)) {
    if (out.hints.length >= %(max)d) break;
    try {
      const as = (l.getAttribute('as') || '').toLowerCase();
      const rel = (l.getAttribute('rel') || '').toLowerCase();
      if (rel !== 'modulepreload' && as !== 'script') continue;
      const rawHref = l.getAttribute('href');
      let href = null;
      try {
        href = rawHref ? new URL(rawHref, document.baseURI).href : null;
      } catch (e) {}
      if (href) out.hints.push({ href: href, rel: rel });
    } catch (e) {}
  }
  return out;
}
""" % {"max": _MAX_SCRIPTS, "cap": _SNIPPET_CAP}

# Async — serviceWorker.getRegistrations() returns a promise. Wrapped
# so pages without SW support (or sandboxed contexts) return [].
SERVICE_WORKER_JS = """
async () => {
  try {
    if (!navigator.serviceWorker
        || !navigator.serviceWorker.getRegistrations) return [];
    const regs = await navigator.serviceWorker.getRegistrations();
    const urls = [];
    for (const r of regs) {
      const w = r.active || r.waiting || r.installing;
      if (w && w.scriptURL) urls.push(w.scriptURL);
    }
    return urls;
  } catch (e) { return []; }
}
"""


def parse_rendered_scripts(raw: object) -> list[RenderedScript]:
    """Parse the SCRIPT_WALK_JS payload. Defensive — junk entries are
    dropped, never raised on."""
    if not isinstance(raw, dict):
        return []
    out: list[RenderedScript] = []
    for entry in raw.get("scripts") or []:
        if not isinstance(entry, dict):
            continue
        src = entry.get("src") if isinstance(entry.get("src"), str) else None
        if src:
            out.append(RenderedScript(
                kind="module" if entry.get("module") else "script_tag",
                src=src,
            ))
            continue
        snippet = entry.get("snippet")
        if not isinstance(snippet, str) or not snippet.strip():
            continue
        text_length = entry.get("textLength")
        truncated = (
            isinstance(text_length, int) and text_length > len(snippet)
        )
        out.append(RenderedScript(
            kind="inline",
            is_inline=True,
            snippet=snippet,
            snippet_hash=sha256_hex(snippet),
            snippet_truncated=truncated,
        ))
    for hint in raw.get("hints") or []:
        if not isinstance(hint, dict):
            continue
        href = hint.get("href")
        rel = hint.get("rel")
        if isinstance(href, str) and href and isinstance(rel, str):
            out.append(RenderedScript(kind=rel, src=href))
    return out


async def capture_scripts(page, tel: BrowserTelemetry) -> None:
    """Collect rendered scripts + service-worker registrations into
    *tel*. Failures append an error note; never raise."""
    try:
        raw = await page.evaluate(SCRIPT_WALK_JS)
        tel.rendered_scripts.extend(parse_rendered_scripts(raw))
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"script walk failed: {type(exc).__name__}")
    try:
        sw_urls = await page.evaluate(SERVICE_WORKER_JS)
        for url in sw_urls if isinstance(sw_urls, list) else []:
            if isinstance(url, str) and url:
                tel.rendered_scripts.append(
                    RenderedScript(kind="service_worker", src=url)
                )
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"service-worker probe failed: {type(exc).__name__}")
