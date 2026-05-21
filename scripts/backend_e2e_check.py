#!/usr/bin/env python3
"""WebHound full-stack E2E validation script.

Runs against a live docker-compose deployment (default: http://localhost:8000).
Uses only stdlib — no external deps required.

Usage:
    python scripts/backend_e2e_check.py [--target URL] [--wade]

    --target URL   URL to scan (default: https://example.com)
    --wade         Run a second scan to validate WADE comparison (adds ~2 min)

Exit codes: 0 = all checks passed, 1 = one or more checks failed.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Config (override via env or CLI)
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8000"
TIMEOUT = 10
SCAN_POLL_TIMEOUT = 180  # seconds to wait for a scan to complete
SCAN_POLL_INTERVAL = 5
MAX_WAIT_SECONDS = 90

_SCAN_TARGET = "https://example.com"
_RUN_WADE_COMPARISON = False


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _request(
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
) -> tuple[int, Any]:
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return 0, {"_error": str(exc)}


def get(path: str, token: str | None = None) -> tuple[int, Any]:
    return _request("GET", path, token=token)


def post(path: str, body: dict, token: str | None = None) -> tuple[int, Any]:
    return _request("POST", path, body=body, token=token)


def patch(path: str, body: dict, token: str | None = None) -> tuple[int, Any]:
    return _request("PATCH", path, body=body, token=token)


def delete(path: str, token: str | None = None) -> tuple[int, Any]:
    return _request("DELETE", path, token=token)


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

_results: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    _results.append((name, passed, detail))
    marker = "✓" if passed else "✗"
    print(f"  [{status}] {marker} {name}" + (f"  ({detail})" if detail else ""))
    return passed


# ---------------------------------------------------------------------------
# Infrastructure checks
# ---------------------------------------------------------------------------


def wait_for_api() -> bool:
    print("  Waiting for API…")
    deadline = time.time() + MAX_WAIT_SECONDS
    while time.time() < deadline:
        status, body = get("/health")
        if status == 200 and body.get("status") == "ok":
            return check("GET /health → 200 ok", True)
        time.sleep(3)
    return check("GET /health → 200 ok", False, f"timed out after {MAX_WAIT_SECONDS}s")


def check_db_health() -> bool:
    status, body = get("/health/db")
    ok = status == 200 and body.get("database") == "ok"
    return check("GET /health/db → database ok", ok, body.get("database", str(status)))


def check_worker_health() -> bool:
    status, body = get("/health/worker")
    ok = status == 200 and body.get("broker") == "ok"
    return check("GET /health/worker → broker ok", ok, body.get("broker", str(status)))


def check_openapi() -> bool:
    status, body = get("/openapi.json")
    ok = status == 200 and body.get("info", {}).get("title") == "WebHound API"
    return check("GET /openapi.json → correct title", ok, str(status))


# ---------------------------------------------------------------------------
# Auth checks
# ---------------------------------------------------------------------------


def register_and_login() -> str | None:
    email = f"e2e_{int(time.time())}@example.com"
    password = "E2ePassword1!"

    status, body = post("/auth/register", {"email": email, "password": password})
    if not check("POST /auth/register → 201", status == 201, str(status)):
        return None

    status, body = post("/auth/login", {"email": email, "password": password})
    token = body.get("access_token")
    if not check("POST /auth/login → 200 + token", status == 200 and bool(token), str(status)):
        return None

    status, me = get("/auth/me", token=token)
    check("GET /auth/me → 200 with email", status == 200 and me.get("email") == email, str(status))

    # Verify rejection without token
    status2, _ = get("/auth/me")
    check("GET /auth/me without token → 401", status2 == 401, str(status2))

    return token


# ---------------------------------------------------------------------------
# Website checks
# ---------------------------------------------------------------------------


def create_website(token: str, url: str) -> str | None:
    status, body = post("/websites", {"url": url}, token=token)
    website_id = body.get("id")
    ok = status == 201 and bool(website_id)
    check("POST /websites → 201", ok, str(status))
    return website_id if ok else None


def list_websites(token: str) -> bool:
    status, body = get("/websites", token=token)
    ok = status == 200 and "items" in body and "total" in body
    return check("GET /websites → paginated list", ok, str(status))


def check_ownership_isolation(token: str, website_id: str) -> None:
    email2 = f"e2e2_{int(time.time())}@example.com"
    _, body2 = post("/auth/register", {"email": email2, "password": "E2ePassword2!"})
    _, login2 = post("/auth/login", {"email": email2, "password": "E2ePassword2!"})
    token2 = login2.get("access_token", "")
    if token2:
        status, _ = get(f"/websites/{website_id}", token=token2)
        check("GET /websites/{id} owned by another user → 404", status == 404, str(status))


# ---------------------------------------------------------------------------
# Scan job checks
# ---------------------------------------------------------------------------


def create_scan_job(token: str, website_id: str, *, save_baseline: bool = True) -> str | None:
    status, body = post(
        "/scan-jobs",
        {
            "website_id": website_id,
            "profile": "quick",
            "save_baseline": save_baseline,
            "use_latest_baseline": False,
        },
        token=token,
    )
    job_id = body.get("id")
    ok = status == 201 and bool(job_id)
    check(f"POST /scan-jobs (save_baseline={save_baseline}) → 201", ok, str(status))
    return job_id if ok else None


def poll_scan_job(token: str, job_id: str, label: str = "Scan") -> str | None:
    """Returns status string ('completed' | 'failed' | None on timeout)."""
    print(f"  Polling {label} job {job_id[:8]}…", end="", flush=True)
    deadline = time.time() + SCAN_POLL_TIMEOUT
    while time.time() < deadline:
        status, body = get(f"/scan-jobs/{job_id}", token=token)
        if status != 200:
            print()
            check(f"{label} job polling HTTP ok", False, f"GET returned {status}")
            return None
        job_status = body.get("status", "")
        print(".", end="", flush=True)
        if job_status in ("completed", "failed"):
            print(f" {job_status}")
            ok = job_status == "completed"
            check(f"{label} job completes successfully", ok, f"status={job_status}")
            return job_status
        time.sleep(SCAN_POLL_INTERVAL)
    print(" timeout")
    check(f"{label} job completes within {SCAN_POLL_TIMEOUT}s", False, "timed out")
    return None


def get_scan_result_id(token: str, job_id: str) -> str | None:
    status, body = get(f"/scan-results?scan_job_id={job_id}", token=token)
    items = body.get("items", [])
    if status == 200 and items:
        result_id = items[0].get("id")
        check("GET /scan-results?scan_job_id → result found", bool(result_id), str(status))
        return result_id
    check("GET /scan-results?scan_job_id → result found", False, f"status={status} items={len(items)}")
    return None


# ---------------------------------------------------------------------------
# Scan result detail checks
# ---------------------------------------------------------------------------


def check_scan_result_detail(token: str, result_id: str) -> dict:
    status, body = get(f"/scan-results/{result_id}", token=token)
    ok = status == 200 and "risk_score" in body
    check("GET /scan-results/{id} → detail with risk_score", ok, str(status))
    return body if ok else {}


def check_grouped_findings(token: str, result_id: str) -> int:
    status, body = get(f"/scan-results/{result_id}/grouped-findings?limit=10", token=token)
    ok = status == 200 and "items" in body
    count = body.get("total", 0) if ok else 0
    check(
        f"GET /scan-results/{result_id[:8]}…/grouped-findings → list",
        ok,
        f"total={count}",
    )
    return count


def check_engine_diagnostics(token: str, result_id: str) -> bool:
    status, body = get(f"/scan-results/{result_id}/engine-diagnostics", token=token)
    ok = status == 200 and isinstance(body, list) and len(body) > 0
    engines = [d.get("engine_name", "?") for d in body[:3]] if isinstance(body, list) else []
    return check(
        f"GET /scan-results/{result_id[:8]}…/engine-diagnostics → list",
        ok,
        f"{len(body) if isinstance(body, list) else 0} engines: {engines}",
    )


def check_reports(token: str, result_id: str) -> bool:
    status, body = get(f"/scan-results/{result_id}/reports", token=token)
    ok = status == 200 and isinstance(body, list)
    formats = [r.get("format") for r in body] if isinstance(body, list) else []
    check(
        f"GET /scan-results/{result_id[:8]}…/reports → list",
        ok,
        f"formats: {formats}",
    )
    if ok and formats:
        fmt = formats[0]
        s2, r2 = get(f"/scan-results/{result_id}/reports/{fmt}", token=token)
        check(
            f"GET /scan-results/{result_id[:8]}…/reports/{fmt} → 200",
            s2 == 200 and "format" in r2,
            str(s2),
        )
    return ok


def check_wade_metadata(token: str, result_id: str) -> bool:
    status, body = get(f"/scan-results/{result_id}", token=token)
    if status != 200:
        return check("WADE metadata present in scan result", False, f"HTTP {status}")
    meta = body.get("scanner_metadata") or {}
    has_wade = "wade_baseline_generated" in meta
    generated = meta.get("wade_baseline_generated", False)
    compared = meta.get("wade_compared_to_previous", False)
    anomalies = meta.get("wade_anomaly_count", 0)
    check(
        "scan_result.scanner_metadata has WADE keys",
        has_wade,
        f"generated={generated} compared={compared} anomalies={anomalies}",
    )
    return generated


# ---------------------------------------------------------------------------
# Baseline checks
# ---------------------------------------------------------------------------


def check_baselines(token: str, website_id: str) -> str | None:
    status, body = get(f"/websites/{website_id}/baselines", token=token)
    items = body.get("items", [])
    ok = status == 200 and len(items) > 0
    first_id = items[0].get("id") if items else None
    check(
        f"GET /websites/{website_id[:8]}…/baselines → saved",
        ok,
        f"count={len(items)}",
    )
    if ok:
        s2, b2 = get(f"/websites/{website_id}/baselines/latest", token=token)
        check(
            "GET /websites/{id}/baselines/latest → 200",
            s2 == 200 and "baseline_version" in b2,
            f"version={b2.get('baseline_version')}",
        )
    return first_id


# ---------------------------------------------------------------------------
# Schedule checks
# ---------------------------------------------------------------------------


def check_schedule_crud(token: str, website_id: str) -> bool:
    from datetime import datetime, timezone, timedelta

    next_run = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT09:00:00Z")

    # Create
    status, body = post(
        "/scan-schedules",
        {
            "website_id": website_id,
            "profile": "monitor",
            "frequency": "weekly",
            "is_enabled": True,
            "use_latest_baseline": True,
            "save_baseline": True,
            "next_run_at": next_run,
        },
        token=token,
    )
    sched_id = body.get("id")
    if not check("POST /scan-schedules → 201", status == 201 and bool(sched_id), str(status)):
        return False

    # List
    s2, b2 = get(f"/scan-schedules?website_id={website_id}", token=token)
    check(
        "GET /scan-schedules?website_id → list",
        s2 == 200 and len(b2.get("items", [])) > 0,
        str(s2),
    )

    # Update (disable)
    s3, b3 = patch(f"/scan-schedules/{sched_id}", {"is_enabled": False}, token=token)
    check(
        "PATCH /scan-schedules/{id} → is_enabled=False",
        s3 == 200 and b3.get("is_enabled") is False,
        str(s3),
    )

    # Delete
    s4, _ = delete(f"/scan-schedules/{sched_id}", token=token)
    check("DELETE /scan-schedules/{id} → 204", s4 == 204, str(s4))
    return True


# ---------------------------------------------------------------------------
# Notification checks
# ---------------------------------------------------------------------------


def check_notifications(token: str) -> bool:
    status, body = get("/notifications", token=token)
    ok = status == 200 and "items" in body
    total = body.get("total", 0) if ok else 0
    check("GET /notifications → paginated list", ok, f"total={total}")

    # Unread count
    s2, b2 = get("/notifications/unread-count", token=token)
    check(
        "GET /notifications/unread-count → count field",
        s2 == 200 and "count" in b2,
        f"count={b2.get('count')}",
    )

    # Mark all read
    s3, b3 = patch("/notifications/read-all", {}, token=token)
    check("PATCH /notifications/read-all → 200", s3 == 200, str(s3))

    # Verify unread = 0 after mark all
    s4, b4 = get("/notifications/unread-count", token=token)
    check(
        "unread count = 0 after mark-all-read",
        s4 == 200 and b4.get("count", -1) == 0,
        f"count={b4.get('count')}",
    )

    # Filter by type
    s5, b5 = get("/notifications?type=scan_completed", token=token)
    check(
        "GET /notifications?type=scan_completed → 200",
        s5 == 200 and "items" in b5,
        str(s5),
    )
    return ok


# ---------------------------------------------------------------------------
# WADE comparison validation (optional, --wade flag)
# ---------------------------------------------------------------------------


def run_wade_comparison(token: str, website_id: str) -> None:
    print("\n[WADE Comparison — second scan]")

    status, body = post(
        "/scan-jobs",
        {
            "website_id": website_id,
            "profile": "quick",
            "save_baseline": True,
            "use_latest_baseline": True,
        },
        token=token,
    )
    job_id = body.get("id")
    if not check("POST /scan-jobs (use_latest_baseline=True) → 201", status == 201, str(status)):
        return

    final_status = poll_scan_job(token, job_id, label="WADE comparison")
    if final_status != "completed":
        return

    result_id = get_scan_result_id(token, job_id)
    if not result_id:
        return

    s, body = get(f"/scan-results/{result_id}", token=token)
    if s != 200:
        check("WADE comparison scan result accessible", False, str(s))
        return

    meta = body.get("scanner_metadata") or {}
    compared = meta.get("wade_compared_to_previous", False)
    anomaly_count = meta.get("wade_anomaly_count", 0)
    check(
        "Second scan has wade_compared_to_previous=True",
        compared,
        f"compared={compared} anomalies={anomaly_count}",
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _print_summary() -> int:
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [name for name, ok, _ in _results if not ok]
    total = len(_results)
    print("\n" + "=" * 65)
    print(f"Results: {passed}/{total} passed" + (f", {len(failed)} FAILED" if failed else " — all green"))
    if failed:
        print("\nFailed checks:")
        for name in failed:
            print(f"  ✗ {name}")
    print("=" * 65)
    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    global _SCAN_TARGET, _RUN_WADE_COMPARISON

    args = sys.argv[1:]
    if "--wade" in args:
        _RUN_WADE_COMPARISON = True
        args = [a for a in args if a != "--wade"]
    if "--target" in args:
        idx = args.index("--target")
        if idx + 1 < len(args):
            _SCAN_TARGET = args[idx + 1]

    print("=" * 65)
    print(f"WebHound E2E Validation  →  {BASE_URL}")
    print(f"Scan target: {_SCAN_TARGET}")
    print("=" * 65)

    print("\n[Infrastructure]")
    if not wait_for_api():
        print("\nAPI is not reachable — aborting.")
        return 1
    check_db_health()
    check_worker_health()
    check_openapi()

    print("\n[Auth]")
    token = register_and_login()
    if not token:
        print("\nAuth failed — aborting.")
        _print_summary()
        return 1

    print("\n[Websites]")
    website_id = create_website(token, _SCAN_TARGET)
    list_websites(token)
    if website_id:
        check_ownership_isolation(token, website_id)

    print("\n[Scan Execution]")
    if not website_id:
        print("  (skipped — no website)")
    else:
        job_id = create_scan_job(token, website_id, save_baseline=True)
        result_id = None
        if job_id:
            final = poll_scan_job(token, job_id)
            if final == "completed":
                result_id = get_scan_result_id(token, job_id)

        print("\n[Scan Results]")
        if result_id:
            check_scan_result_detail(token, result_id)
            check_grouped_findings(token, result_id)
            check_engine_diagnostics(token, result_id)
            check_reports(token, result_id)
            check_wade_metadata(token, result_id)
        else:
            print("  (skipped — scan did not complete)")

        print("\n[Baselines]")
        check_baselines(token, website_id)

        print("\n[Schedules]")
        check_schedule_crud(token, website_id)

        if _RUN_WADE_COMPARISON:
            run_wade_comparison(token, website_id)

    print("\n[Notifications]")
    check_notifications(token)

    return _print_summary()


if __name__ == "__main__":
    sys.exit(main())
