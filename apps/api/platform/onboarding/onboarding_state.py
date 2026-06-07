# WebHound API — apps/api/platform/onboarding/onboarding_state.py
# Phase-19 Task 9: derive a customer's onboarding checklist + the single
# next action from account/site/scan facts. Pure — the caller gathers the
# booleans from the DB; this turns them into a guided checklist the
# frontend renders.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OnboardingFacts:
    account_created: bool = True       # if we have a user, this is true
    email_verified: bool = False
    domain_added: bool = False
    domain_verified: bool = False
    first_scan_started: bool = False
    first_report_viewed: bool = False
    monitoring_enabled: bool = False
    is_paid_plan: bool = False
    billing_active: bool = False


# Ordered steps. ``required`` steps gate "onboarding complete"; the
# billing step only applies to paid plans.
_STEPS = (
    ("account_created", "Create your account", True, None),
    ("email_verified", "Verify your email", True, None),
    ("domain_added", "Add your first website", True, None),
    ("domain_verified", "Verify domain ownership", True, None),
    ("first_scan_started", "Run your first scan", True, None),
    ("first_report_viewed", "Review your first report", False, None),
    ("monitoring_enabled", "Turn on monitoring", False, None),
    ("billing_active", "Activate your subscription", True, "is_paid_plan"),
)


@dataclass
class OnboardingState:
    steps: list[dict[str, Any]] = field(default_factory=list)
    completed_count: int = 0
    total_count: int = 0
    percent_complete: int = 0
    is_complete: bool = False
    next_step: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "completed_count": self.completed_count,
            "total_count": self.total_count,
            "percent_complete": self.percent_complete,
            "is_complete": self.is_complete,
            "next_step": self.next_step,
        }


def derive_onboarding_state(facts: OnboardingFacts) -> OnboardingState:
    """Turn the facts into a checklist + the next action to guide the
    user (Task 9)."""
    steps: list[dict[str, Any]] = []
    required_total = 0
    required_done = 0
    next_step: dict[str, Any] | None = None

    for key, label, required, gate in _STEPS:
        # Gated steps (billing) only apply when the gate is true.
        if gate is not None and not getattr(facts, gate, False):
            continue
        done = bool(getattr(facts, key, False))
        entry = {"key": key, "label": label, "done": done,
                 "required": required}
        steps.append(entry)
        if required:
            required_total += 1
            if done:
                required_done += 1
        if not done and next_step is None:
            next_step = entry

    total = len(steps)
    done = sum(1 for s in steps if s["done"])
    pct = int(round(done / total * 100)) if total else 100
    return OnboardingState(
        steps=steps, completed_count=done, total_count=total,
        percent_complete=pct,
        is_complete=(required_done == required_total),
        next_step=next_step)
