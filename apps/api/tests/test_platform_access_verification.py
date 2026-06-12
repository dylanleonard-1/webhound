"""Phase-2 Platform Access — verification engine mapping (Verified / Partially-
Verified / Failed / Blocked). Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.services.platform_access import (
    STATE_COMPLETE,
    STATE_FAILED,
    STATE_VERIFIED,
    compute_state,
)


def test_success_is_verified():
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status="pending",
                         verification_result="success") == STATE_VERIFIED


def test_partial_is_verified():
    # LIMITED → partial: the scanner got through (verified) but coverage is
    # restricted; still a VERIFIED state, flagged partial in the view.
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status="pending",
                         verification_result="partial") == STATE_VERIFIED


def test_blocked_is_failed():
    assert compute_state(challenge_detected=True, provider="vercel",
                         trusted_status="pending",
                         verification_result="blocked") == STATE_FAILED


def test_failed_is_failed():
    assert compute_state(challenge_detected=False, provider="vercel",
                         trusted_status="pending",
                         verification_result="failed") == STATE_FAILED


def test_active_trusted_overrides_to_complete():
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status="active") == STATE_COMPLETE
