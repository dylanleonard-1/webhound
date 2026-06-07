# WebHound — scanner/webhound/auth/login_recording.py
# Phase-10 Task 4: login-flow recordings — a safe, replayable sequence
# of navigation + field-fill + click steps that establishes a session.
#
# SECRET POSTURE:
#   * Passwords / secret field values are NEVER stored in plaintext. A
#     recording references secrets by a named placeholder
#     (``{{password}}``) resolved at replay time from a secret the
#     customer supplies out-of-band. The recording itself is safe to
#     persist.
#   * Replay is constrained: only the recorded steps run, only the
#     recorded selectors are touched, and the final step must confirm a
#     success indicator. The auth_guard still vetoes any step that looks
#     destructive, so a tampered recording can't be weaponised.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.auth.auth_guard import DESTRUCTIVE_RE

# Field names whose values are secret and must be referenced by
# placeholder, never stored.
_SECRET_FIELD_RE = re.compile(
    r"pass(word|wd|code)?|secret|token|otp|mfa|2fa|pin|cvv|ssn",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(r"^\{\{[a-zA-Z0-9_]+\}\}$")


class StepAction(str, Enum):
    NAVIGATE = "navigate"     # go to a URL
    FILL = "fill"             # type into a field (value or placeholder)
    CLICK = "click"           # click a selector (submit-login etc.)
    WAIT_FOR = "wait_for"     # wait for a selector / URL (success indicator)


@dataclass
class LoginStep:
    action: StepAction
    selector: str | None = None     # CSS/role selector for fill/click/wait
    url: str | None = None          # for navigate / wait_for url
    value: str | None = None        # literal value OR {{placeholder}} for secrets
    is_secret: bool = False

    def to_dict(self) -> dict[str, Any]:
        # Secret values are never serialised — only the placeholder name.
        safe_value = self.value
        if self.is_secret and not (self.value and _PLACEHOLDER_RE.match(self.value)):
            safe_value = "{{redacted}}"
        return {
            "action": self.action.value,
            "selector": self.selector,
            "url": self.url,
            "value": safe_value,
            "is_secret": self.is_secret,
        }


@dataclass
class LoginRecording:
    """A replayable login flow plus its success indicator."""

    name: str
    steps: list[LoginStep] = field(default_factory=list)
    success_url_contains: str | None = None
    success_selector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "success_url_contains": self.success_url_contains,
            "success_selector": self.success_selector,
        }


@dataclass
class RecordingValidation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_recording(rec: LoginRecording) -> RecordingValidation:
    """Reject recordings that store secrets in plaintext, contain
    destructive clicks, or have no success indicator."""
    errors: list[str] = []
    warnings: list[str] = []

    if not rec.steps:
        errors.append("recording has no steps")
    if not rec.success_url_contains and not rec.success_selector:
        errors.append("recording has no success indicator")

    for i, step in enumerate(rec.steps):
        # Secret hygiene: a fill into a secret-looking field MUST use a
        # placeholder, never a literal.
        if step.action == StepAction.FILL:
            looks_secret = bool(
                step.selector and _SECRET_FIELD_RE.search(step.selector)
            ) or step.is_secret
            if looks_secret:
                if not (step.value and _PLACEHOLDER_RE.match(step.value)):
                    errors.append(
                        f"step {i}: secret field value must be a "
                        "{{placeholder}}, not a literal"
                    )
        # No destructive clicks in a login recording.
        if step.action == StepAction.CLICK and step.selector:
            if DESTRUCTIVE_RE.search(step.selector):
                # login/sign in are the legitimate exception for a login
                # recording — allow those, block the rest.
                if not re.search(r"log\s*in|signin|sign-in|sign\s*in",
                                 step.selector, re.IGNORECASE):
                    errors.append(
                        f"step {i}: click selector looks destructive: "
                        f"{step.selector!r}"
                    )
        # Navigation steps must not target destructive endpoints.
        if step.action == StepAction.NAVIGATE and step.url:
            from webhound.auth.auth_guard import check_navigation
            if not check_navigation(step.url).allowed:
                errors.append(f"step {i}: navigate URL is destructive")

    return RecordingValidation(ok=not errors, errors=errors, warnings=warnings)


def resolve_secret_steps(
    rec: LoginRecording, secrets: dict[str, str],
) -> list[dict[str, Any]]:
    """Produce replay-ready steps with placeholders resolved from
    *secrets*. Returns plain dicts the runner can execute; the resolved
    values exist only in this returned list (handed to Playwright, never
    stored). Missing secrets raise so we never submit a blank credential."""
    resolved: list[dict[str, Any]] = []
    for i, step in enumerate(rec.steps):
        value = step.value
        if value and _PLACEHOLDER_RE.match(value):
            key = value[2:-2]
            if key not in secrets:
                raise KeyError(f"step {i}: missing secret {key!r}")
            value = secrets[key]
        resolved.append({
            "action": step.action.value,
            "selector": step.selector,
            "url": step.url,
            "value": value,
        })
    return resolved


def recording_from_dict(data: dict[str, Any]) -> LoginRecording:
    """Parse a recording dict (e.g. customer upload). Defensive."""
    steps = []
    for raw in data.get("steps") or []:
        if not isinstance(raw, dict):
            continue
        try:
            action = StepAction(raw.get("action"))
        except ValueError:
            continue
        steps.append(LoginStep(
            action=action,
            selector=raw.get("selector"),
            url=raw.get("url"),
            value=raw.get("value"),
            is_secret=bool(raw.get("is_secret")),
        ))
    return LoginRecording(
        name=str(data.get("name") or "login"),
        steps=steps,
        success_url_contains=data.get("success_url_contains"),
        success_selector=data.get("success_selector"),
    )
