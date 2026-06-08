# WebHound — apps/api/admin/read_scan_telemetry.py
# Internal/admin CLI to read back the persisted telemetry + browser_pass for a
# scan job (by job id). Read-only. Pairs with run_scan.py to verify the
# browser-telemetry checklist after an admin DEEP scan.
#
# Usage:
#   python -m apps.api.admin.read_scan_telemetry --job-id <uuid>

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from apps.api.services.admin_scan import AdminScanError, read_scan_telemetry


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhound-admin-read-scan-telemetry",
        description="Internal admin: read persisted telemetry for a scan job.")
    p.add_argument("--job-id", required=True, dest="job_id")
    return p


async def _run(args: argparse.Namespace) -> int:
    from apps.api.database import get_session_factory
    factory = get_session_factory()
    async with factory() as db:
        try:
            payload = await read_scan_telemetry(db, args.job_id)
        except AdminScanError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 2
    print(json.dumps(payload, indent=2, default=str))
    return 0


def main() -> None:
    sys.exit(asyncio.run(_run(_parser().parse_args())))


if __name__ == "__main__":
    main()
