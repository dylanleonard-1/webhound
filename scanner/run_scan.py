# WebHound — scanner/run_scan.py
# Baseline-aware passive scan runner with profile support.
#
# Usage examples:
#   python run_scan.py https://example.com
#   python run_scan.py https://example.com --profile quick
#   python run_scan.py https://example.com --profile standard --save-baseline
#   python run_scan.py https://example.com --profile monitor \
#       --use-latest-baseline --save-baseline
#   python run_scan.py https://example.com --baseline-store /var/webhound/baselines

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from webhound.core.orchestrator import Scanner
from webhound.core.scan_profiles import PROFILE_NAMES, get_profile
from webhound.models.target import Target
from webhound.reporting.json_report import JsonReport
from webhound.reporting.summary_builder import SummaryBuilder
from webhound.wade.baseline_store import BaselineStore

_REPORTS_DIR = Path(__file__).parent / "reports"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhound",
        description="WebHound — passive website security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Profiles:",
            "  quick    – 5 pages, depth 1, 1 req/s (fast surface check)",
            "  standard – 25 pages, depth 2, 1 req/s (recommended)",
            "  deep     – 100 pages, depth 4, 0.5 req/s (thorough)",
            "  monitor  – 10 pages, depth 1, 0.5 req/s (baseline comparison)",
        ]),
    )
    parser.add_argument("url", help="Target URL to scan (must include scheme).")
    parser.add_argument(
        "--profile",
        choices=list(PROFILE_NAMES),
        default="standard",
        metavar="PROFILE",
        help=f"Scan profile: {', '.join(PROFILE_NAMES)}. Default: standard.",
    )
    parser.add_argument(
        "--baseline-store",
        metavar="PATH",
        default=None,
        help="Directory for storing WADE baselines. Default: ~/.webhound/baselines.",
    )
    parser.add_argument(
        "--use-latest-baseline",
        action="store_true",
        help="Load the most recent saved baseline for this target before scanning.",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save a new WADE baseline to disk after the scan completes.",
    )
    parser.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help=f"Directory for JSON reports. Default: {_REPORTS_DIR}.",
    )
    return parser


def _report_filename(url: str, profile_name: str) -> str:
    """Return a filesystem-safe report filename derived from the target URL."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "unknown").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{hostname}_{profile_name}_{timestamp}.json"


async def _run(args: argparse.Namespace) -> int:
    profile = get_profile(args.profile)
    options = profile.to_scan_options()

    store = BaselineStore(args.baseline_store) if args.baseline_store else BaselineStore()

    previous_baseline = None
    if args.use_latest_baseline:
        previous_baseline = store.get_latest_baseline(args.url)
        if previous_baseline is None:
            print(
                f"[WebHound] No saved baseline for {args.url} — "
                "running without comparison."
            )
        else:
            print(
                f"[WebHound] Loaded baseline from scan "
                f"{previous_baseline.scan_id[:8]}… "
                f"({previous_baseline.page_count} pages)"
            )

    target = Target.from_url(args.url, scan_options=options)
    scanner = Scanner(target, previous_baseline=previous_baseline)

    print(f"[WebHound] Profile:  {profile.name} — {profile.description}")
    print(
        f"[WebHound] Target:   {args.url}  "
        f"max_pages={profile.max_pages}  "
        f"max_depth={profile.max_depth}  "
        f"rps={profile.rate_limit_rps}"
    )
    print()

    result = await scanner.scan()

    # ------------------------------------------------------------------
    # WADE baseline persistence
    # ------------------------------------------------------------------
    if args.save_baseline and scanner.current_baseline is not None:
        saved_path = store.save_baseline(scanner.current_baseline)
        print(f"[WebHound] Baseline saved → {saved_path}")

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------
    print(SummaryBuilder().build(result))

    # ------------------------------------------------------------------
    # JSON report to reports/ directory
    # ------------------------------------------------------------------
    output_dir = Path(args.output_dir) if args.output_dir else _REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = _report_filename(args.url, profile.name)
    report_path = output_dir / filename

    with report_path.open("w", encoding="utf-8") as fh:
        json.dump(JsonReport().build(result), fh, indent=2, default=str)

    print(f"\n[WebHound] JSON report → {report_path}")

    return 1 if result.status.value == "failed" else 0


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
