# WebHound API — apps/api/platform/health/production_readiness.py
# Phase-19 Task 14: a production-readiness report aggregator. Combines
# the env validation + live dependency probes (DB/Redis/scanner-import)
# into one structured verdict for an ops dashboard / launch checklist.
#
# The PROBES are pure callables the caller supplies (so this stays
# unit-testable + decoupled from the real DB/Redis); a thin async helper
# wires the real probes in the readiness endpoint.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from apps.api.platform.security.env_validator import validate_env


@dataclass
class ReadinessCheck:
    name: str
    ok: bool
    critical: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "critical": self.critical,
                "detail": self.detail}


@dataclass
class ProductionReadinessReport:
    ready: bool
    app_env: str
    checks: list[ReadinessCheck] = field(default_factory=list)

    @property
    def failing_critical(self) -> list[str]:
        return [c.name for c in self.checks if c.critical and not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "app_env": self.app_env,
            "failing_critical": self.failing_critical,
            "checks": [c.to_dict() for c in self.checks],
        }


def _check_scanner_importable() -> ReadinessCheck:
    try:
        import webhound  # noqa: F401
        from webhound.core.orchestrator import Scanner  # noqa: F401
        return ReadinessCheck("scanner_importable", True, True,
                              "webhound scanner imports")
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck("scanner_importable", False, True,
                              f"import error: {type(exc).__name__}")


def build_readiness_report(
    *,
    env: Mapping[str, str] | None = None,
    db_ok: bool | None = None,
    redis_ok: bool | None = None,
    worker_ok: bool | None = None,
    migrations_current: bool | None = None,
) -> ProductionReadinessReport:
    """Assemble the readiness verdict. Dependency probe results are passed
    in (None = not probed / unknown, treated as non-blocking warning)."""
    env_res = validate_env(env)
    checks: list[ReadinessCheck] = []

    checks.append(ReadinessCheck(
        "env", env_res.ok, True,
        "ok" if env_res.ok else
        f"missing critical: {env_res.missing_critical}; "
        f"insecure: {env_res.insecure_defaults}"))

    checks.append(_check_scanner_importable())

    def _dep(name: str, val: bool | None, critical: bool) -> None:
        if val is None:
            checks.append(ReadinessCheck(name, True, False, "not probed"))
        else:
            checks.append(ReadinessCheck(
                name, val, critical, "ok" if val else "unreachable"))

    _dep("database", db_ok, True)
    _dep("redis", redis_ok, True)
    _dep("worker", worker_ok, False)
    _dep("migrations_current", migrations_current, False)

    # Browser discovery status (non-critical, but high-impact for modern
    # JS/SPA sites). Surfaced so operators can SEE when deep scans are
    # running without rendered-DOM/SPA/browser-API discovery — the most
    # common reason deep scans look identical to static scans.
    import os as _os
    _env = env if env is not None else _os.environ
    browser_on = str(_env.get("WEBHOUND_BROWSER_ENABLED", "0")) == "1"
    checks.append(ReadinessCheck(
        "browser_discovery", True, False,
        "enabled" if browser_on else
        "disabled — deep scans skip rendered-DOM/SPA/browser-API discovery "
        "(set WEBHOUND_BROWSER_ENABLED=1 on a worker with Playwright/Chromium "
        "installed)"))

    ready = all(c.ok for c in checks if c.critical)
    return ProductionReadinessReport(
        ready=ready, app_env=env_res.app_env, checks=checks)
