# WebHound — scanner/webhound/auth/__init__.py
# Phase-10 authenticated scanning (read-only).

from webhound.auth.auth_context import (
    AuthContext,
    AuthMode,
    AuthPageContext,
    AuthSource,
    SessionCookieMeta,
)
from webhound.auth.auth_guard import (
    AuthSafetyViolation,
    GuardDecision,
    assert_read_only,
    check_click,
    check_navigation,
    is_safe_method,
)
from webhound.auth.login_recording import (
    LoginRecording,
    LoginStep,
    StepAction,
    recording_from_dict,
    resolve_secret_steps,
    validate_recording,
)
from webhound.auth.session_loader import LoadedSession, load_session_cookies
from webhound.auth.storage_state import (
    LoadedStorageState,
    load_storage_state,
)

__all__ = [
    "AuthContext", "AuthMode", "AuthPageContext", "AuthSource",
    "SessionCookieMeta", "AuthSafetyViolation", "GuardDecision",
    "assert_read_only", "check_click", "check_navigation",
    "is_safe_method", "LoginRecording", "LoginStep", "StepAction",
    "recording_from_dict", "resolve_secret_steps", "validate_recording",
    "LoadedSession", "load_session_cookies", "LoadedStorageState",
    "load_storage_state",
]
