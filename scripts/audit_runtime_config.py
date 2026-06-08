#!/usr/bin/env python3
"""WebHound runtime-config diagnostic (FIX 14).

Prints a SAFE, secret-free snapshot of how this deployment is wired so an
operator can confirm a release is configured correctly before/after deploy.

Hard safety contract:
  * NEVER prints a secret VALUE — only whether a var is present (names only) and
    boolean feature-flag states.
  * NEVER imports the application (apps.api.* / worker.* / webhound.*), NEVER
    opens a DB or Redis connection, NEVER calls alembic. Everything here is
    static: os.environ reads + source-file parsing + importlib.find_spec.

Run:  python scripts/audit_runtime_config.py
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Truthy env values for boolean flags.
_TRUE = {"1", "true", "yes", "on"}


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


def _present(name: str) -> bool:
    return bool((os.getenv(name) or "").strip())


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _ok(b: bool) -> str:
    return "yes" if b else "no "


def header(title: str) -> None:
    print()
    print(f"== {title} " + "=" * max(0, 60 - len(title)))


# ---------------------------------------------------------------------------
# Migration head (static — parse files, never call alembic)
# ---------------------------------------------------------------------------

_REVISION_RE = re.compile(r'^revision\s*:?.*=\s*["\']([^"\']+)["\']', re.M)
_DOWN_RE = re.compile(r'^down_revision\s*:?.*=\s*(?:["\']([^"\']+)["\']|None)', re.M)


def migration_head() -> tuple[str | None, int, str | None]:
    """Return (head_revision, count, error)."""
    versions = ROOT / "apps" / "api" / "migrations" / "versions"
    if not versions.is_dir():
        return None, 0, "versions dir not found"
    chain: dict[str, str | None] = {}
    for path in sorted(versions.glob("*.py")):
        if not path.name[0].isdigit():
            continue
        text = _read(path)
        rev_m = _REVISION_RE.search(text)
        down_m = _DOWN_RE.search(text)
        if not rev_m or not down_m:
            continue
        chain[rev_m.group(1)] = down_m.group(1)
    if not chain:
        return None, 0, "no migrations parsed"
    downs = {d for d in chain.values() if d is not None}
    heads = [r for r in chain if r not in downs]
    if len(heads) != 1:
        return None, len(chain), f"expected 1 head, found {sorted(heads)}"
    return heads[0], len(chain), None


# ---------------------------------------------------------------------------
# Source-wiring probes (static greps, no imports)
# ---------------------------------------------------------------------------

def _contains(path: Path, needle: str) -> bool:
    return needle in _read(path)


def scanner_engines() -> list[tuple[str, bool]]:
    orch = ROOT / "scanner" / "webhound" / "core" / "orchestrator.py"
    text = _read(orch)
    checks = [
        ("VulnerableLibsEngine instantiated", "VulnerableLibsEngine()" in text),
        ("VulnerableLibsEngine run in pipeline", "_run_vulnerable_libs(" in text),
        ("ThreatIntelEngine", "ThreatIntelEngine(" in text),
        ("FormRiskEngine", "FormRiskEngine()" in text),
        ("InputAnalysisEngine", "InputAnalysisEngine()" in text),
        ("SecretScannerEngine", "SecretScannerEngine()" in text),
    ]
    # Forms discovery engines (FIX 12) — exist as modules.
    forms = ROOT / "scanner" / "webhound" / "engines" / "forms"
    for mod, cls in (
        ("form_discovery.py", "FormDiscoveryEngine"),
        ("parameter_discovery.py", "ParameterDiscoveryEngine"),
        ("safe_input_tester.py", "SafeInputTester"),
    ):
        checks.append((f"forms.{cls}", _contains(forms / mod, f"class {cls}")))
    return checks


def worker_reliability() -> list[tuple[str, bool]]:
    celery = ROOT / "worker" / "celery_app.py"
    scan = ROOT / "worker" / "scan_tasks.py"
    mon = ROOT / "worker" / "monitoring_tasks.py"
    ctext = _read(celery)
    return [
        ("Celery soft time limit set", "task_soft_time_limit=" in ctext),
        ("Celery hard time limit set", "task_time_limit=" in ctext),
        ("Per-task scan soft/hard limit", "soft_time_limit=" in _read(scan)),
        ("SoftTimeLimitExceeded handled", "SoftTimeLimitExceeded" in _read(scan)),
        ("Stale-job reaper task defined", "def reap_stale_scan_jobs" in _read(mon)
         or "reap_stale_scan_jobs" in _read(mon)),
        ("Reaper scheduled (beat)", "reap-stale-scan-jobs" in ctext),
        ("Worker heartbeat scheduled", "worker-heartbeat" in ctext),
        ("Scheduled-scan dispatch wired", "dispatch-scheduled-scans" in ctext),
    ]


def notification_wiring() -> list[tuple[str, bool]]:
    sj = ROOT / "worker" / "scan_tasks.py"
    nt = ROOT / "worker" / "notification_tasks.py"
    nd = ROOT / "apps" / "api" / "services" / "notification_delivery.py"
    email = ROOT / "apps" / "api" / "services" / "email.py"
    return [
        ("Email delivery task defined", _contains(nt, "deliver_notification_email")),
        ("Scan task enqueues email", _contains(sj, "deliver_notification_email")),
        ("Delivery service present", nd.is_file()),
        ("Resend->SMTP failover present", _contains(email, "failing over to SMTP")
         or _contains(email, "fail over")),
    ]


def cancellation_wiring() -> list[tuple[str, bool]]:
    orch = ROOT / "scanner" / "webhound" / "core" / "orchestrator.py"
    sj_svc = ROOT / "apps" / "api" / "services" / "scan_jobs.py"
    model = ROOT / "apps" / "api" / "models" / "scan_job.py"
    return [
        ("ScanCancelled defined", _contains(orch, "class ScanCancelled")),
        ("Cancel hook in pipeline", _contains(orch, "_raise_if_cancelled")),
        ("API revoke on cancel", _contains(sj_svc, "_revoke_scan_task")),
        ("cancellation_requested column", _contains(model, "cancellation_requested")),
        ("heartbeat_at column", _contains(model, "heartbeat_at")),
    ]


# ---------------------------------------------------------------------------
# Env presence (NAMES ONLY — never values)
# ---------------------------------------------------------------------------

_ENV_GROUPS: dict[str, list[str]] = {
    "Core": ["APP_ENV", "DATABASE_URL", "REDIS_URL", "SECRET_KEY",
             "API_BASE_URL", "FRONTEND_URL"],
    "Email (Resend/SMTP)": ["RESEND_API_KEY", "SMTP_HOST", "SMTP_PORT",
                            "SMTP_USERNAME", "SMTP_PASSWORD"],
    "Billing (Stripe)": ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
                         "STRIPE_PRICE_PRO_MONTHLY", "STRIPE_PRICE_SHIELD_MONTHLY",
                         "STRIPE_PRICE_ENTERPRISE_MONTHLY"],
    "OAuth": ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
              "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"],
    "Threat intel / AI": ["ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY",
                          "URLHAUS_API_KEY"],
    "Observability": ["SENTRY_DSN"],
}

_FEATURE_FLAGS = [
    "WEBHOUND_AI_ENABLED", "WEBHOUND_BROWSER_ENABLED", "WEBHOUND_ASM_ALLOW_NETWORK",
    "ENABLE_URLHAUS", "NOTIFICATIONS_ENABLED", "SMTP_FALLBACK_ENABLED",
    "SMTP_USE_TLS", "RATE_LIMIT_ENABLED",
    "ADMIN_VERIFY_BYPASS", "ADMIN_QUOTA_BYPASS", "ADMIN_BYPASS_ALLOW_IN_PROD",
    "DEV_ALLOW_UNVERIFIED_SCANS", "DEV_SKIP_DOMAIN_VERIFICATION",
]

_NUMERIC_SETTINGS = [
    ("SCAN_SOFT_TIME_LIMIT", "600"),
    ("SCAN_HARD_TIME_LIMIT", "720"),
    ("SCAN_STALE_QUEUED_SECONDS", "900"),
    ("SCAN_STALE_RUNNING_SECONDS", "1800"),
    ("WORKER_CONCURRENCY", "2"),
    ("WEBHOUND_DEFAULT_ENGINE_TIMEOUT", "60"),
]


def notification_delivery_configured() -> tuple[bool, str]:
    enabled = _bool_env("NOTIFICATIONS_ENABLED")
    resend = _present("RESEND_API_KEY")
    smtp = _bool_env("SMTP_FALLBACK_ENABLED") and _present("SMTP_HOST")
    provider = resend or smtp
    if not enabled:
        return False, "NOTIFICATIONS_ENABLED off (in-app only; no email sent)"
    if not provider:
        return False, "enabled but NO provider (set RESEND_API_KEY or SMTP_FALLBACK_ENABLED+SMTP_HOST)"
    which = "resend" if resend else "smtp-fallback"
    return True, f"enabled, provider={which}"


def browser_available() -> tuple[bool, str]:
    has_playwright = importlib.util.find_spec("playwright") is not None
    flag = _bool_env("WEBHOUND_BROWSER_ENABLED")
    if not has_playwright:
        return False, "playwright not installed (static crawl only)"
    return True, f"playwright installed; WEBHOUND_BROWSER_ENABLED={'on' if flag else 'off'}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Best-effort UTF-8 stdout so the em-dashes render on Windows consoles too.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    print("WebHound runtime-config diagnostic (safe / secret-free)")
    print(f"repo: {ROOT}")
    print(f"APP_ENV: {os.getenv('APP_ENV', '(unset)')}")

    header("Environment variables (presence only — values never shown)")
    for group, names in _ENV_GROUPS.items():
        print(f"  [{group}]")
        for name in names:
            print(f"    {_ok(_present(name))} {name}")

    header("Feature flags")
    for name in _FEATURE_FLAGS:
        raw = os.getenv(name)
        state = "(default)" if raw is None else ("on" if _bool_env(name) else "off")
        print(f"    {name} = {state}")

    header("Worker reliability settings")
    for name, default in _NUMERIC_SETTINGS:
        raw = os.getenv(name)
        shown = raw if raw is not None else f"{default} (default)"
        print(f"    {name} = {shown}")
    for label, ok in worker_reliability():
        print(f"    {_ok(ok)} {label}")

    header("Scanner engines wired")
    for label, ok in scanner_engines():
        print(f"    {_ok(ok)} {label}")

    header("Notification delivery")
    configured, detail = notification_delivery_configured()
    print(f"    {_ok(configured)} delivery configured — {detail}")
    for label, ok in notification_wiring():
        print(f"    {_ok(ok)} {label}")

    header("Cancellation / heartbeat wiring")
    for label, ok in cancellation_wiring():
        print(f"    {_ok(ok)} {label}")

    header("Browser discovery")
    ok, detail = browser_available()
    print(f"    {_ok(ok)} {detail}")

    header("Database migrations (static — alembic NOT called)")
    head, count, err = migration_head()
    if err:
        print(f"    migration head: ERROR — {err}")
    else:
        print(f"    migration head (static): {head}   (chain length: {count})")
        print("    apply with:  railway run alembic upgrade head")
        print("    verify with: alembic current   (should match the head above)")

    print()
    print("done — no secrets printed, no app imported, no DB/Redis touched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
