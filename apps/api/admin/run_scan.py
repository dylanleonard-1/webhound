# WebHound — apps/api/admin/run_scan.py
# Internal/admin CLI to run ANY scan profile on demand through the production
# pipeline. Authorization = ability to run this in the API/worker env (e.g.
# `railway run -- python -m apps.api.admin.run_scan ...`). Every run is audited.
#
# Usage:
#   python -m apps.api.admin.run_scan \
#     --url https://webhoundsecurity.com \
#     --profile deep \
#     --reason "verify browser telemetry" \
#     --triggered-by "internal-dev"
#
# Profiles: quick | standard | deep | enterprise | monitor | baseline
# (baseline = deep + save a fresh WADE baseline).

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from apps.api.services.admin_scan import (
    ALLOWED_PROFILES,
    AdminScanError,
    run_admin_scan,
)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhound-admin-run-scan",
        description="Internal admin: run any scan profile on demand.")
    p.add_argument("--url", required=True, help="Target URL (scheme optional).")
    p.add_argument("--profile", required=True, choices=ALLOWED_PROFILES)
    p.add_argument("--reason", required=True, help="Audit reason (required).")
    p.add_argument("--triggered-by", required=True, dest="triggered_by",
                   help="Who is running this (audit, required).")
    p.add_argument("--internal-test-mode", action="store_true",
                   help="Bypass the ownership/allowlist gate (audited). Use "
                        "only for domains we control.")
    p.add_argument("--save-baseline", action="store_true",
                   help="Persist a WADE baseline after the scan.")
    p.add_argument("--use-latest-baseline", action="store_true",
                   help="Load the latest baseline for comparison.")
    return p


async def _run(args: argparse.Namespace) -> int:
    from apps.api.database import get_session_factory
    factory = get_session_factory()
    async with factory() as db:
        try:
            payload = await run_admin_scan(
                db, url=args.url, profile=args.profile, reason=args.reason,
                triggered_by=args.triggered_by,
                internal_test_mode=args.internal_test_mode,
                save_baseline=True if args.save_baseline else None,
                use_latest_baseline=args.use_latest_baseline)
            await db.commit()
        except AdminScanError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 2
    print(json.dumps(payload, indent=2))
    return 0


def main() -> None:
    sys.exit(asyncio.run(_run(_parser().parse_args())))


if __name__ == "__main__":
    main()
