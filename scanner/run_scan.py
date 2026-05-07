# WebHound — live passive scan runner
# Usage: python run_scan.py

from __future__ import annotations

import asyncio
import json
import sys

from webhound.core.orchestrator import Scanner
from webhound.models.target import ScanOptions, Target
from webhound.reporting.json_report import JsonReport
from webhound.reporting.summary_builder import SummaryBuilder


TARGET_URL = "https://www.chicagopepperbros.com/"

OPTIONS = ScanOptions(
    max_pages=10,
    max_depth=2,
    rate_limit_rps=1.0,       # 1 req/s — polite
    request_timeout_seconds=15,
    verify_tls=True,
    respect_robots_txt=True,
    include_subdomains=False,
)


async def main() -> None:
    target = Target.from_url(TARGET_URL, scan_options=OPTIONS)
    scanner = Scanner(target)

    print(f"[WebHound] Starting passive scan: {TARGET_URL}")
    print(f"           max_pages={OPTIONS.max_pages}  max_depth={OPTIONS.max_depth}"
          f"  rps={OPTIONS.rate_limit_rps}")
    print()

    result = await scanner.scan()

    # ------------------------------------------------------------------
    # Summary report
    # ------------------------------------------------------------------
    print(SummaryBuilder().build(result))

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------
    out_path = "scan_output.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(JsonReport().build(result), fh, indent=2, default=str)

    print(f"\nJSON report → {out_path}")

    # Return non-zero exit code if scan failed
    if result.status.value == "failed":
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
