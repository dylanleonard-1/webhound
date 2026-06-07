# WebHound — tests/test_auth_loaders.py
# Phase-10 Tasks 2-4: session-cookie, storage-state, and login-recording
# loaders. Central contract: scope validation, expiration handling, and
# NO secret leakage into our models / diagnostics.

from __future__ import annotations

import time

import pytest

from webhound.auth.login_recording import (
    LoginRecording,
    LoginStep,
    StepAction,
    recording_from_dict,
    resolve_secret_steps,
    validate_recording,
)
from webhound.auth.session_loader import load_session_cookies
from webhound.auth.storage_state import load_storage_state

_DOMAINS = {"example.com"}


# ---------------------------------------------------------------------------
# Session cookies (Task 2)
# ---------------------------------------------------------------------------


def test_load_session_cookie_in_scope() -> None:
    res = load_session_cookies([
        {"name": "session", "value": "SECRET-TOKEN-XYZ",
         "domain": ".example.com", "secure": True, "httpOnly": True,
         "sameSite": "Lax"},
    ], allowed_domains=_DOMAINS)
    assert res.has_session
    assert res.looks_like_real_session
    # Browser cookie keeps the value (for injection)...
    assert res.browser_cookies[0]["value"] == "SECRET-TOKEN-XYZ"
    # ...but the meta record stores only length, never the value.
    meta = res.cookie_meta[0]
    assert meta.value_length == len("SECRET-TOKEN-XYZ")
    assert "SECRET-TOKEN-XYZ" not in repr(meta)
    assert "SECRET-TOKEN-XYZ" not in repr(res.cookie_meta)
    assert res.auth_domains == {"example.com"}


def test_out_of_scope_cookie_skipped_by_name_only() -> None:
    res = load_session_cookies([
        {"name": "evil", "value": "LEAK", "domain": "attacker.test"},
    ], allowed_domains=_DOMAINS)
    assert not res.has_session
    assert any("evil" in s and "out of scope" in s for s in res.skipped)
    # The value must never appear in diagnostics.
    assert "LEAK" not in repr(res.skipped)


def test_expired_cookie_skipped() -> None:
    res = load_session_cookies([
        {"name": "session", "value": "x", "domain": "example.com",
         "expires": time.time() - 100},
    ], allowed_domains=_DOMAINS)
    assert not res.has_session
    assert any("expired" in s for s in res.skipped)


def test_earliest_expiry_tracked() -> None:
    soon = time.time() + 100
    later = time.time() + 10_000
    res = load_session_cookies([
        {"name": "a", "value": "x", "domain": "example.com", "expires": later},
        {"name": "session", "value": "y", "domain": "example.com",
         "expires": soon},
    ], allowed_domains=_DOMAINS)
    assert res.earliest_expiry == soon


def test_malformed_cookie_payload_safe() -> None:
    assert load_session_cookies("nope", allowed_domains=_DOMAINS).errors
    res = load_session_cookies([None, 7, {"name": "x"}],
                               allowed_domains=_DOMAINS)
    assert not res.has_session


# ---------------------------------------------------------------------------
# Storage state (Task 3)
# ---------------------------------------------------------------------------


def test_load_storage_state_filters_scope_and_strips_localstorage() -> None:
    payload = {
        "cookies": [
            {"name": "sid", "value": "SECRET", "domain": "example.com",
             "secure": True, "httpOnly": True},
            {"name": "x", "value": "other", "domain": "evil.test"},
        ],
        "origins": [
            {"origin": "https://example.com",
             "localStorage": [{"name": "token", "value": "SECRET-LS"}]},
            {"origin": "https://evil.test",
             "localStorage": [{"name": "a", "value": "b"}]},
        ],
    }
    res = load_storage_state(payload, allowed_domains=_DOMAINS)
    assert res.has_session
    # Only in-scope cookie kept.
    assert [c["name"] for c in res.storage_state["cookies"]] == ["sid"]
    # Only in-scope origin kept; localStorage reduced to a key count.
    assert res.origins == ["https://example.com"]
    assert res.local_storage_key_counts["https://example.com"] == 1
    # No localStorage VALUE anywhere in our summary models.
    assert "SECRET-LS" not in repr(res.cookie_meta)
    assert "SECRET-LS" not in repr(res.local_storage_key_counts)
    assert "SECRET-LS" not in repr(res.origins)


def test_storage_state_invalid_json() -> None:
    res = load_storage_state("{not json", allowed_domains=_DOMAINS)
    assert res.errors and not res.has_session


def test_storage_state_from_json_string() -> None:
    import json
    s = json.dumps({"cookies": [
        {"name": "sid", "value": "v", "domain": "example.com"}], "origins": []})
    res = load_storage_state(s, allowed_domains=_DOMAINS)
    assert res.has_session


# ---------------------------------------------------------------------------
# Login recordings (Task 4)
# ---------------------------------------------------------------------------


def _valid_recording() -> LoginRecording:
    return LoginRecording(
        name="login",
        steps=[
            LoginStep(StepAction.NAVIGATE, url="https://example.com/login"),
            LoginStep(StepAction.FILL, selector="#email",
                      value="user@example.com"),
            LoginStep(StepAction.FILL, selector="#password",
                      value="{{password}}", is_secret=True),
            LoginStep(StepAction.CLICK, selector="button#login"),
            LoginStep(StepAction.WAIT_FOR, url="/dashboard"),
        ],
        success_url_contains="/dashboard",
    )


def test_valid_recording_passes() -> None:
    assert validate_recording(_valid_recording()).ok is True


def test_plaintext_password_rejected() -> None:
    rec = _valid_recording()
    rec.steps[2].value = "hunter2"          # literal secret — not allowed
    v = validate_recording(rec)
    assert v.ok is False
    assert any("placeholder" in e for e in v.errors)


def test_recording_serialization_never_leaks_secret() -> None:
    rec = _valid_recording()
    rec.steps[2].value = "hunter2"          # even if a literal slips in
    blob = repr(rec.to_dict())
    assert "hunter2" not in blob            # redacted on serialise
    assert "{{redacted}}" in blob or "{{password}}" in blob


def test_destructive_click_in_recording_rejected() -> None:
    rec = _valid_recording()
    rec.steps[3].selector = "button#delete-account"
    assert validate_recording(rec).ok is False


def test_no_success_indicator_rejected() -> None:
    rec = _valid_recording()
    rec.success_url_contains = None
    rec.success_selector = None
    assert validate_recording(rec).ok is False


def test_resolve_secret_steps_injects_value() -> None:
    rec = _valid_recording()
    steps = resolve_secret_steps(rec, {"password": "real-pw"})
    pw_step = next(s for s in steps if s["selector"] == "#password")
    assert pw_step["value"] == "real-pw"


def test_resolve_missing_secret_raises() -> None:
    with pytest.raises(KeyError):
        resolve_secret_steps(_valid_recording(), {})


def test_recording_from_dict_roundtrip() -> None:
    rec = _valid_recording()
    parsed = recording_from_dict(rec.to_dict())
    assert parsed.name == "login"
    assert len(parsed.steps) == 5
    assert parsed.success_url_contains == "/dashboard"
