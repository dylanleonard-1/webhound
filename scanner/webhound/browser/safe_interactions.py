# WebHound — webhound/browser/safe_interactions.py
# Phase-6B: bounded, conservative page interactions that surface
# lazy-loaded content (nav menus, accordions, modals, infinite-scroll
# sections) WITHOUT ever acting on application state.
#
# SAFETY CONTRACT (deny rules win over everything):
#   * NEVER submit a form — any element inside a <form> is blocked
#     outright, as is anything with type=submit. This also covers
#     "subscribe" buttons that submit newsletter forms.
#   * NEVER click elements whose accessible text matches the
#     transactional deny-list (submit/send/pay/purchase/buy/checkout/
#     delete/remove/confirm/login/sign in/register/subscribe/...).
#   * NEVER click links (navigation) — only buttons/expanders.
#   * A click additionally requires a POSITIVE safe signal
#     (aria-expanded / aria-haspopup / <summary> / data-toggle, or
#     menu/expand-flavoured text). Absence of a deny match is NOT
#     sufficient.
#   * Hard cap on click count; every click is recorded in telemetry.

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

from webhound.browser.models import BrowserTelemetry

logger = logging.getLogger(__name__)

_MAX_CANDIDATES = 100
_DEFAULT_MAX_CLICKS = 5
_POST_CLICK_WAIT_S = 0.3

# Transactional / state-changing vocabulary. Word-boundary matched
# against the element's combined accessible text.
DENY_RE = re.compile(
    r"\b("
    r"submit|send|pay|purchase|buy|checkout|order|"
    r"delete|remove|confirm|apply|"
    r"log\s*in|login|sign\s*in|sign\s*up|sign\s*out|log\s*out|logout|"
    r"register|subscribe|unsubscribe|"
    r"add\s+to\s+(cart|bag|basket)|cart|"
    r"save|update|upload|download|install|"
    r"accept|agree|consent|"
    r"share|post|publish|comment|reply|vote|like|follow"
    r")\b",
    re.IGNORECASE,
)

# Positive signals that an element only reveals content.
ALLOW_TEXT_RE = re.compile(
    r"\b("
    r"menu|nav|navigation|open|expand|collapse|show|more|toggle|"
    r"accordion|dropdown|details|options|filters?|view\s+all|"
    r"read\s+more|see\s+(all|more)|learn\s+more"
    r")\b",
    re.IGNORECASE,
)

CANDIDATE_SELECTOR = (
    'button, [role="button"], summary, '
    '[aria-expanded], [aria-haspopup], [data-toggle]'
)

CANDIDATE_WALK_JS = """
() => {
  const sel = '%(selector)s';
  const out = [];
  let i = 0;
  for (const el of document.querySelectorAll(sel)) {
    if (out.length >= %(max)d) break;
    try {
      out.push({
        index: i,
        tag: el.tagName.toLowerCase(),
        text: ((el.innerText || el.textContent || '')
               .trim().slice(0, 80)),
        aria: el.getAttribute('aria-label') || '',
        type: (el.getAttribute('type') || '').toLowerCase(),
        name: el.getAttribute('name') || '',
        title: el.getAttribute('title') || '',
        href: el.getAttribute('href'),
        disabled: el.hasAttribute('disabled'),
        inForm: !!el.closest('form'),
        expander: el.hasAttribute('aria-expanded')
                  || el.hasAttribute('aria-haspopup')
                  || el.hasAttribute('data-toggle')
                  || el.tagName.toLowerCase() === 'summary',
      });
    } catch (e) {}
    i++;
  }
  return out;
}
""" % {"selector": CANDIDATE_SELECTOR.replace("'", "\\'"),
       "max": _MAX_CANDIDATES}

SCROLL_JS = """
async () => {
  try {
    const h = document.body ? document.body.scrollHeight : 0;
    window.scrollTo(0, Math.floor(h / 2));
    await new Promise(r => setTimeout(r, 150));
    window.scrollTo(0, document.body ? document.body.scrollHeight : 0);
  } catch (e) {}
}
"""


@dataclass(frozen=True)
class ClickDecision:
    allowed: bool
    reason: str
    label: str


def decide_click(meta: dict) -> ClickDecision:
    """Pure decision for one candidate element. Deny rules first —
    a deny match always wins, even when a positive signal exists."""
    label = " ".join(str(meta.get(k) or "") for k in
                     ("text", "aria", "name", "title", "type")).strip()
    short = (meta.get("text") or meta.get("aria") or "?")[:60]

    if meta.get("disabled"):
        return ClickDecision(False, "disabled", short)
    if meta.get("href"):
        return ClickDecision(False, "navigation_link", short)
    if (meta.get("type") or "").lower() == "submit":
        return ClickDecision(False, "submit_button", short)
    if meta.get("inForm"):
        return ClickDecision(False, "inside_form", short)
    if DENY_RE.search(label):
        return ClickDecision(False, "deny_list", short)

    if meta.get("expander"):
        return ClickDecision(True, "expander_attribute", short)
    if ALLOW_TEXT_RE.search(label):
        return ClickDecision(True, "allow_text", short)
    return ClickDecision(False, "no_positive_signal", short)


async def perform_safe_interactions(
    page,
    tel: BrowserTelemetry,
    *,
    max_clicks: int = _DEFAULT_MAX_CLICKS,
) -> None:
    """Scroll the page, then click up to ``max_clicks`` elements that
    pass :func:`decide_click`. Every action and every block is
    recorded on the telemetry. Defensive throughout — never raises."""
    # 1. Scroll — triggers lazy loaders / IntersectionObservers.
    try:
        await page.evaluate(SCROLL_JS)
        tel.interactions.append("scroll: bottom")
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"scroll failed: {type(exc).__name__}")

    # 2. Candidate walk.
    try:
        candidates = await page.evaluate(CANDIDATE_WALK_JS)
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"interaction walk failed: {type(exc).__name__}")
        return
    if not isinstance(candidates, list):
        return

    clicks = 0
    for meta in candidates:
        if not isinstance(meta, dict):
            continue
        decision = decide_click(meta)
        if not decision.allowed:
            tel.blocked_interactions += 1
            continue
        if clicks >= max_clicks:
            break
        idx = meta.get("index")
        if not isinstance(idx, int) or idx < 0:
            continue
        try:
            await page.locator(CANDIDATE_SELECTOR).nth(idx).click(
                timeout=1_000, no_wait_after=True,
            )
            clicks += 1
            tel.interactions.append(
                f"click[{decision.reason}]: {decision.label}"
            )
            await asyncio.sleep(_POST_CLICK_WAIT_S)
        except Exception:  # noqa: BLE001
            # Element moved / covered / detached — fine, skip it.
            continue
