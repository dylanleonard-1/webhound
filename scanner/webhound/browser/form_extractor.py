# WebHound — webhound/browser/form_extractor.py
# Phase-6B: rendered-form extraction from the live (post-hydration)
# DOM. Lazy-loaded and JS-injected forms never appear in static HTML,
# so this is the only way the form engines can see them.
#
# SAFE-MODE CONTRACT:
#   * The DOM walk is read-only — getAttribute() calls only.
#   * No element is ever focused, filled, clicked, or submitted.
#   * Attribute reads go through getAttribute, never property access,
#     so DOM clobbering (<input name="action">) can't poison values.

from __future__ import annotations

import logging
from urllib.parse import urlparse

from webhound.browser.models import (
    BrowserTelemetry,
    RenderedForm,
    RenderedFormField,
)

logger = logging.getLogger(__name__)

_MAX_FORMS = 200
_MAX_FIELDS_PER_FORM = 100

FORM_WALK_JS = """
() => {
  const forms = [];
  for (const f of document.querySelectorAll('form')) {
    if (forms.length >= %(max_forms)d) break;
    try {
      const fields = [];
      let hasPassword = false;
      let hasFile = false;
      const hiddenNames = [];
      for (const el of f.querySelectorAll('input, select, textarea')) {
        if (fields.length >= %(max_fields)d) break;
        const type = (el.getAttribute('type')
                      || el.tagName || '').toLowerCase();
        const name = el.getAttribute('name');
        if (type === 'password') hasPassword = true;
        if (type === 'file') hasFile = true;
        if (type === 'hidden' && name) hiddenNames.push(name);
        fields.push({ name: name, type: type });
      }
      const rawAction = f.getAttribute('action');
      let action = null;
      try {
        action = rawAction
          ? new URL(rawAction, document.baseURI).href : null;
      } catch (e) {}
      forms.push({
        action: action,
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        fields: fields,
        hasPassword: hasPassword,
        hasFile: hasFile,
        hiddenNames: hiddenNames,
      });
    } catch (e) {}
  }
  return forms;
}
""" % {"max_forms": _MAX_FORMS, "max_fields": _MAX_FIELDS_PER_FORM}


def _registrable(host: str) -> str:
    """Registrable-domain approximation shared with network_capture."""
    from webhound.browser.network_capture import _registrable as _r
    return _r(host)


def _action_is_external(action: str | None, page_url: str | None) -> bool:
    if not action or not page_url:
        return False
    try:
        a_host = (urlparse(action).hostname or "").lower()
        p_host = (urlparse(page_url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return False
    if not a_host or not p_host:
        return False
    return _registrable(a_host) != _registrable(p_host)


def parse_rendered_forms(
    raw: object, page_url: str | None,
) -> list[RenderedForm]:
    """Parse the FORM_WALK_JS payload into RenderedForm models.

    Defensive throughout — the payload crossed the browser boundary,
    so every field is type-checked and junk entries are dropped
    rather than raised on."""
    if not isinstance(raw, list):
        return []
    out: list[RenderedForm] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        fields = tuple(
            RenderedFormField(
                name=f.get("name") if isinstance(f.get("name"), str) else None,
                input_type=str(f.get("type") or "text"),
            )
            for f in (entry.get("fields") or [])
            if isinstance(f, dict)
        )
        action = (
            entry.get("action")
            if isinstance(entry.get("action"), str) else None
        )
        hidden = tuple(
            n for n in (entry.get("hiddenNames") or [])
            if isinstance(n, str) and n
        )
        out.append(RenderedForm(
            action=action,
            method=str(entry.get("method") or "GET").upper(),
            fields=fields,
            has_password_field=bool(entry.get("hasPassword")),
            page_url=page_url,
            has_file_input=bool(entry.get("hasFile")),
            hidden_field_names=hidden,
            action_is_external=_action_is_external(action, page_url),
        ))
    return out


async def capture_forms(page, tel: BrowserTelemetry) -> None:
    """Run the form walk against *page* and store results on *tel*.
    Failures append an error note; never raise."""
    try:
        raw = await page.evaluate(FORM_WALK_JS)
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"form walk failed: {type(exc).__name__}")
        return
    tel.rendered_forms.extend(
        parse_rendered_forms(raw, tel.final_url or tel.page_url)
    )
