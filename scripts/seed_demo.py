#!/usr/bin/env python3
"""WebHound demo seed script.

Creates a demo user, demo website, and optionally triggers a scan and schedule.
Idempotent: safe to run multiple times — skips resources that already exist.

Usage:
    python3 scripts/seed_demo.py [--api-url URL] [--no-scan] [--no-schedule]

    --api-url URL    API base URL (default: http://localhost:8000)
    --no-scan        Skip creating a scan job
    --no-schedule    Skip creating a weekly schedule

Authorization notice:
    The default demo target is https://example.com, which is operated by IANA
    and is explicitly designated for use in documentation and examples.
    When testing against other targets you MUST own or have explicit written
    authorization to scan that domain.  WebHound performs passive, read-only
    reconnaissance only — no exploitation or form submission occurs.

Exit codes: 0 = success, 1 = failure.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Demo credentials — used only for local dev/beta.  Change in any shared env.
# ---------------------------------------------------------------------------
DEMO_EMAIL = "demo@webhound.dev"
DEMO_PASSWORD = "DemoHound42!"
DEMO_WEBSITE_URL = "https://example.com"
DEMO_DISPLAY_NAME = "Example.com (Demo)"

BASE_URL = "http://localhost:8000"
TIMEOUT = 10
SCAN_POLL_TIMEOUT = 300
SCAN_POLL_INTERVAL = 5


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _request(
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict]:
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
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


def get(path: str, token: str | None = None) -> tuple[int, dict]:
    return _request("GET", path, token=token)


def post(path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
    return _request("POST", path, body=body, token=token)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def wait_for_api() -> bool:
    print("Checking API health…", end="", flush=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        status, body = get("/health")
        if status == 200 and body.get("status") == "ok":
            print(" ok")
            return True
        print(".", end="", flush=True)
        time.sleep(2)
    print(" TIMEOUT")
    return False


def get_or_create_user() -> str | None:
    """Register demo user; if already exists, log in instead. Returns token."""
    status, body = post(
        "/auth/register",
        {"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )
    if status == 201:
        print(f"  Created user: {DEMO_EMAIL}")
    elif status == 409:
        print(f"  User already exists: {DEMO_EMAIL}")
    else:
        print(f"  ERROR registering user: HTTP {status} {body}")
        return None

    status, body = post(
        "/auth/login",
        {"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )
    if status != 200:
        print(f"  ERROR logging in: HTTP {status} {body}")
        return None
    token = body.get("access_token")
    print("  Logged in — token acquired")
    return token


def get_or_create_website(token: str) -> str | None:
    """Add demo website; if it already exists for this user, return its id."""
    status, body = post(
        "/websites",
        {"url": DEMO_WEBSITE_URL, "display_name": DEMO_DISPLAY_NAME},
        token=token,
    )
    if status == 201:
        website_id = body["id"]
        print(f"  Created website: {DEMO_WEBSITE_URL}  (id={website_id[:8]}…)")
        return website_id

    if status == 409:
        # Already registered — find it in the list
        s2, b2 = get("/websites?limit=100", token=token)
        if s2 == 200:
            for w in b2.get("items", []):
                if w.get("url") == DEMO_WEBSITE_URL:
                    website_id = w["id"]
                    print(
                        f"  Website already exists: {DEMO_WEBSITE_URL}  (id={website_id[:8]}…)"
                    )
                    return website_id
        print(f"  ERROR: website exists but could not retrieve id (HTTP {s2})")
        return None

    print(f"  ERROR creating website: HTTP {status} {body}")
    return None


def trigger_scan(token: str, website_id: str) -> str | None:
    status, body = post(
        "/scan-jobs",
        {
            "website_id": website_id,
            "profile": "quick",
            "save_baseline": True,
            "use_latest_baseline": False,
        },
        token=token,
    )
    if status != 201:
        print(f"  ERROR creating scan job: HTTP {status} {body}")
        return None
    job_id = body["id"]
    print(f"  Scan job queued: {job_id[:8]}…  (profile=quick)")
    return job_id


def poll_scan(token: str, job_id: str) -> str | None:
    """Returns final status string or None on timeout."""
    print("  Waiting for scan to complete…", end="", flush=True)
    deadline = time.time() + SCAN_POLL_TIMEOUT
    while time.time() < deadline:
        status, body = get(f"/scan-jobs/{job_id}", token=token)
        if status != 200:
            print(f" HTTP {status}")
            return None
        job_status = body.get("status", "")
        if job_status in ("completed", "failed"):
            print(f" {job_status}")
            return job_status
        print(".", end="", flush=True)
        time.sleep(SCAN_POLL_INTERVAL)
    print(" timed out")
    return None


def create_schedule(token: str, website_id: str) -> str | None:
    next_run = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
        "%Y-%m-%dT09:00:00Z"
    )
    status, body = post(
        "/scan-schedules",
        {
            "website_id": website_id,
            "profile": "standard",
            "frequency": "weekly",
            "is_enabled": True,
            "use_latest_baseline": True,
            "save_baseline": True,
            "next_run_at": next_run,
        },
        token=token,
    )
    if status == 201:
        sched_id = body["id"]
        print(f"  Schedule created: weekly standard scan  (id={sched_id[:8]}…)")
        return sched_id
    print(f"  ERROR creating schedule: HTTP {status} {body}")
    return None


def check_notifications(token: str) -> None:
    status, body = get("/notifications", token=token)
    if status == 200:
        total = body.get("total", 0)
        print(f"  Notifications: {total} in inbox")
    else:
        print(f"  Could not fetch notifications: HTTP {status}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    global BASE_URL

    args = sys.argv[1:]
    run_scan_flag = "--no-scan" not in args
    run_schedule = "--no-schedule" not in args
    if "--api-url" in args:
        idx = args.index("--api-url")
        if idx + 1 < len(args):
            BASE_URL = args[idx + 1].rstrip("/")

    print("=" * 60)
    print("WebHound — demo seed script")
    print(f"  API:     {BASE_URL}")
    print(f"  User:    {DEMO_EMAIL}")
    print(f"  Target:  {DEMO_WEBSITE_URL}")
    print("=" * 60)

    print("\n[API Health]")
    if not wait_for_api():
        print("\nAPI is not reachable. Start the stack first:")
        print("  docker compose up -d")
        return 1

    print("\n[Demo User]")
    token = get_or_create_user()
    if not token:
        return 1

    print("\n[Demo Website]")
    website_id = get_or_create_website(token)
    if not website_id:
        return 1

    job_id: str | None = None
    if run_scan_flag:
        print("\n[Scan Job]")
        job_id = trigger_scan(token, website_id)
        if job_id:
            final = poll_scan(token, job_id)
            if final == "completed":
                print("  Scan completed successfully")
            elif final == "failed":
                print("  Scan finished with status=failed (check worker logs)")
            else:
                print("  Scan timed out — results may still arrive when worker finishes")

    if run_schedule:
        print("\n[Schedule]")
        create_schedule(token, website_id)

    print("\n[Notifications]")
    check_notifications(token)

    print("\n" + "=" * 60)
    print("Demo data ready.")
    print()
    print("  Login:     POST /auth/login")
    print(f"  Email:     {DEMO_EMAIL}")
    print(f"  Password:  {DEMO_PASSWORD}")
    print()
    print("  Frontend:  http://localhost:3000")
    print("  API docs:  http://localhost:8000/docs")
    print()
    print("Run the full demo flow described in docs/first-run.md")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
