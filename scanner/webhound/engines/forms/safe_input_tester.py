# WebHound — scanner/webhound/engines/forms/safe_input_tester.py
# FIX 12 — safe (passive) input "tester".
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ ACTIVE INPUT TESTING IS INTENTIONALLY DISABLED.                          │
# │                                                                         │
# │ WebHound is a PASSIVE, safe-mode scanner. This module NEVER submits a    │
# │ form, NEVER sends a POST/PUT/PATCH/DELETE, NEVER fills a field, and      │
# │ NEVER transmits a payload of any kind. It only *describes*, read-only,   │
# │ what an active tester WOULD examine on each discovered form so the       │
# │ report can be explicit that no intrusive testing was performed.          │
# │                                                                         │
# │ Active/intrusive testing (injection, fuzzing, auth brute force) is out   │
# │ of scope by design and must never be added here without an explicit,     │
# │ separately-authorised engagement model.                                  │
# └─────────────────────────────────────────────────────────────────────────┘

from __future__ import annotations

from dataclasses import dataclass

from webhound.core.extractor import ExtractedForm, PageArtifacts

_ENGINE = "safe_input_tester"

# What we'd want to *look at* on an input — purely descriptive. Reading these
# attributes is the entire extent of this engine's interaction with a form.
_TESTABLE_TYPES = frozenset({
    "text", "search", "email", "url", "tel", "password",
    "number", "textarea", "hidden",
})


@dataclass(frozen=True)
class InputTestPlan:
    """A read-only description of inputs that active testing WOULD target.

    ``submitted`` is always False and ``method`` is always "none" — these fields
    exist to make the passive posture explicit in the report, not to record any
    action taken.
    """

    source_page: str | None
    action: str | None
    candidate_inputs: tuple[str, ...]
    submitted: bool = False          # invariant: never True
    method: str = "none"            # invariant: nothing is ever sent
    note: str = "passive: no form submitted, no value sent"


class SafeInputTester:
    """Passive no-op input "tester".

    ``analyze(artifacts)`` returns one :class:`InputTestPlan` per form listing
    the inputs an active tester *would* probe — but this engine performs NO
    active testing whatsoever: it never submits a form and never sends a request.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[InputTestPlan]:
        plans: list[InputTestPlan] = []
        for form in (artifacts.forms or []):
            plans.append(self._plan(form, artifacts.url))
        return plans

    def _plan(self, form: ExtractedForm, page_url: str | None) -> InputTestPlan:
        candidates = tuple(
            i.name for i in form.inputs
            if i.name and (i.input_type or "text").lower() in _TESTABLE_TYPES
        )
        return InputTestPlan(
            source_page=page_url,
            action=form.action_url or form.action,
            candidate_inputs=candidates,
        )


__all__ = ["InputTestPlan", "SafeInputTester"]
