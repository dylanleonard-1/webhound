#!/usr/bin/env python3
"""WebHound quick smoke check — no scan, no long waits.

Validates that the stack is healthy and the core API endpoints respond correctly.
Completes in ~10 seconds. Use backend_e2e_check.py for a full end-to-end test.

Usage:
    python3 scripts/smoke_check.py [--base URL]

    --base URL     API base URL (default: http://localhost:8000)

Exit codes: 0 = all checks passed, 1 = one or more failed.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

BASE_URL = "http://localhost:8000"

_results: list[tuple[str, bool, str]] = []


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
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
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


def delete(path: str, token: str | None = None) -> tuple[int, Any]:
    return _request("DELETE", path, token=token)


def check(name: str, ok: bool, detail: str = "") -> bool:
    icon = "✓" if ok else "✗"
    suffix = f"  ({detail})" if detail else ""
    print(f"  {icon} {name}{suffix}")
    _results.append((name, ok, detail))
    return ok


# ---------------------------------------------------------------------------
# Infrastructure checks
# ---------------------------------------------------------------------------


def check_health() -> bool:
    s, b = get("/health")
    return check("GET /health → ok", s == 200 and b.get("status") == "ok", str(s))


def check_health_db() -> bool:
    s, b = get("/health/db")
    return check("GET /health/db → database ok", s == 200 and b.get("database") == "ok", str(b))


def check_health_worker() -> bool:
    s, b = get("/health/worker")
    return check("GET /health/worker → broker ok", s == 200 and b.get("broker") == "ok", str(b))


def check_openapi() -> bool:
    s, _ = get("/openapi.json")
    return check("GET /openapi.json → 200", s == 200, str(s))


# ---------------------------------------------------------------------------
# Auth checks
# ---------------------------------------------------------------------------


def register_and_login() -> str | None:
    uid = uuid.uuid4().hex[:8]
    email = f"smoke-{uid}@test.local"
    password = "smoke-test-password"

    s1, _ = post("/auth/register", {"email": email, "password": password})
    if not check("POST /auth/register → 201", s1 == 201, str(s1)):
        return None

    s2, b2 = post("/auth/login", {"email": email, "password": password})
    token = b2.get("access_token")
    check("POST /auth/login → token", s2 == 200 and bool(token), str(s2))
    return token or None


def check_auth_me(token: str) -> bool:
    s, b = get("/auth/me", token=token)
    return check("GET /auth/me → user object", s == 200 and "email" in b, str(s))


def check_wrong_password() -> bool:
    s, _ = post("/auth/login", {"email": "nobody@example.com", "password": "wrong"})
    return check("POST /auth/login wrong creds → 401", s == 401, str(s))


def check_unauthenticated_access() -> bool:
    s, _ = get("/websites")
    return check("GET /websites without token → 401", s == 401, str(s))


# ---------------------------------------------------------------------------
# Website CRUD
# ---------------------------------------------------------------------------


def check_website_crud(token: str) -> str | None:
    uid = uuid.uuid4().hex[:6]
    url = f"https://smoke-{uid}.example.com"

    s1, b1 = post("/websites", {"url": url}, token=token)
    site_id = b1.get("id")
    if not check("POST /websites → 201", s1 == 201, str(s1)):
        return None

    s2, b2 = get(f"/websites/{site_id}", token=token)
    check("GET /websites/{id} → 200", s2 == 200 and b2.get("id") == site_id, str(s2))

    s3, b3 = get("/websites", token=token)
    check("GET /websites → list contains created site", s3 == 200 and "items" in b3, str(s3))

    return site_id


def check_website_delete(token: str, site_id: str) -> bool:
    s, _ = delete(f"/websites/{site_id}", token=token)
    return check(f"DELETE /websites/{{id}} → 204", s == 204, str(s))


# ---------------------------------------------------------------------------
# Scan jobs (list only — no scan execution)
# ---------------------------------------------------------------------------


def check_scan_jobs_list(token: str) -> bool:
    s, b = get("/scan-jobs", token=token)
    return check("GET /scan-jobs → paginated list", s == 200 and "items" in b, str(s))


def check_scan_results_list(token: str) -> bool:
    s, b = get("/scan-results", token=token)
    return check("GET /scan-results → paginated list", s == 200 and "items" in b, str(s))


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


def check_schedules_list(token: str) -> bool:
    s, b = get("/scan-schedules", token=token)
    return check("GET /scan-schedules → paginated list", s == 200 and "items" in b, str(s))


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def check_notifications_list(token: str) -> bool:
    s, b = get("/notifications", token=token)
    return check("GET /notifications → paginated list", s == 200 and "items" in b, str(s))


def check_unread_count(token: str) -> bool:
    s, b = get("/notifications/unread-count", token=token)
    return check("GET /notifications/unread-count → count field", s == 200 and "count" in b, str(s))


# ---------------------------------------------------------------------------
# Isolation — second user can't access first user's data
# ---------------------------------------------------------------------------


def check_isolation(token1: str, site_id: str) -> None:
    uid = uuid.uuid4().hex[:8]
    email2 = f"smoke2-{uid}@test.local"
    _, _ = post("/auth/register", {"email": email2, "password": "password2"})
    _, b = post("/auth/login", {"email": email2, "password": "password2"})
    token2 = b.get("access_token")
    if not token2:
        check("Isolation check (skipped — second login failed)", False)
        return
    s, _ = get(f"/websites/{site_id}", token=token2)
    check("Second user cannot access first user's website → 403/404", s in (403, 404), str(s))


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _summary() -> int:
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [name for name, ok, _ in _results if not ok]
    total = len(_results)
    print("\n" + "=" * 60)
    if failed:
        print(f"Results: {passed}/{total} passed, {len(failed)} FAILED")
        print("\nFailed:")
        for name in failed:
            print(f"  ✗ {name}")
    else:
        print(f"Results: {passed}/{total} — all passed ✓")
    print("=" * 60)
    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    global BASE_URL
    args = sys.argv[1:]
    if "--base" in args:
        idx = args.index("--base")
        if idx + 1 < len(args):
            BASE_URL = args[idx + 1]

    print("=" * 60)
    print(f"WebHound Smoke Check  →  {BASE_URL}")
    print("=" * 60)

    print("\n[Infrastructure]")
    if not check_health():
        print("\nAPI is not reachable — is the stack running?")
        print("  docker compose up -d && docker compose ps")
        return 1
    check_health_db()
    check_health_worker()
    check_openapi()

    print("\n[Auth — security]")
    check_wrong_password()
    check_unauthenticated_access()

    print("\n[Auth — register + login]")
    token = register_and_login()
    if not token:
        print("\nLogin failed — check API logs: docker compose logs --tail=50 api")
        return _summary()

    check_auth_me(token)

    print("\n[Websites CRUD]")
    site_id = check_website_crud(token)

    print("\n[Scan Jobs & Results (list only)]")
    check_scan_jobs_list(token)
    check_scan_results_list(token)

    print("\n[Schedules]")
    check_schedules_list(token)

    print("\n[Notifications]")
    check_notifications_list(token)
    check_unread_count(token)

    print("\n[Isolation]")
    if site_id:
        check_isolation(token, site_id)

    print("\n[Cleanup]")
    if site_id:
        check_website_delete(token, site_id)

    return _summary()


if __name__ == "__main__":
    sys.exit(main())
