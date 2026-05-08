# WebHound — scanner/run_scan.py
# Baseline-aware passive scan runner with profile and output-format support.
#
# Usage examples:
#   python run_scan.py https://example.com
#   python run_scan.py https://example.com --profile quick
#   python run_scan.py https://example.com --profile standard --save-baseline
#   python run_scan.py https://example.com --profile monitor \
#       --use-latest-baseline --save-baseline
#   python run_scan.py https://example.com --baseline-store /var/webhound/baselines
#   python run_scan.py https://example.com --format sarif --format markdown
#   python run_scan.py https://example.com --format all --benchmark
#   python run_scan.py https://example.com --header "X-Custom: value" \
#       --cookie "session=abc" --bearer-token-env WEBHOUND_TOKEN
#   python run_scan.py https://example.com --session-file session.json

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from webhound.core.orchestrator import Scanner
from webhound.core.performance import ScanTelemetry
from webhound.core.scan_profiles import PROFILE_NAMES, get_profile
from webhound.core.session_context import SessionContext, parse_cookie, parse_header
from webhound.models.target import Target
from webhound.reporting.cli_formatter import (
    bold_divider,
    fmt_duration,
    fmt_risk,
    fmt_url,
    thin_divider,
)
from webhound.reporting.csv_report import CsvReport
from webhound.reporting.json_report import JsonReport
from webhound.reporting.markdown_report import MarkdownReport
from webhound.reporting.sarif_report import SarifReport
from webhound.reporting.summary_builder import SummaryBuilder
from webhound.wade.baseline_store import BaselineStore

_REPORTS_DIR = Path(__file__).parent / "reports"
_BAR_WIDTH = 60

_ALL_FORMATS: frozenset[str] = frozenset({"json", "sarif", "csv", "markdown"})
_FORMAT_EXTENSION: dict[str, str] = {
    "json": ".json",
    "sarif": ".sarif",
    "csv": ".csv",
    "markdown": ".md",
}


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------


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
            "",
            "Formats:",
            "  json     – structured JSON (default)",
            "  sarif    – SARIF 2.1.0 (code-scanning integration)",
            "  csv      – flat CSV (spreadsheet / SIEM)",
            "  markdown – human-readable Markdown",
            "  all      – write all of the above",
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
        help=f"Directory for reports. Default: {_REPORTS_DIR}.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif", "csv", "markdown", "all"],
        action="append",
        dest="formats",
        metavar="FORMAT",
        help=(
            "Output format(s): json, sarif, csv, markdown, all. "
            "Repeatable. Default: json."
        ),
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Print a detailed performance table after the scan summary.",
    )

    # ------------------------------------------------------------------
    # Session / authentication flags (passive GET/HEAD only — no login forms)
    # ------------------------------------------------------------------
    parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        metavar="NAME: VALUE",
        help=(
            "Add a custom request header (format: 'Name: value'). Repeatable. "
            "Example: --header 'X-Custom: abc'."
        ),
    )
    parser.add_argument(
        "--cookie",
        action="append",
        dest="cookies",
        metavar="NAME=VALUE",
        help=(
            "Add a custom cookie (format: 'name=value'). Repeatable. "
            "Example: --cookie 'session=abc123'."
        ),
    )
    parser.add_argument(
        "--bearer-token-env",
        metavar="ENV_VAR",
        default=None,
        help=(
            "Load a bearer token from the named environment variable. "
            "The token is never read from the command line directly."
        ),
    )
    parser.add_argument(
        "--session-file",
        metavar="PATH",
        default=None,
        help=(
            "Load session headers and cookies from a JSON file. "
            "No passwords or tokens are read from session files."
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_formats(formats: list[str] | None) -> set[str]:
    """Expand format list, substituting 'all' for the full set."""
    if not formats:
        return {"json"}
    if "all" in formats:
        return set(_ALL_FORMATS)
    return set(formats)


def _report_stem(url: str, profile_name: str) -> str:
    """Return a filesystem-safe filename stem (no extension)."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "unknown").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{hostname}_{profile_name}_{timestamp}"


# Keep the old name available so existing callers are not broken.
def _report_filename(url: str, profile_name: str) -> str:
    return _report_stem(url, profile_name) + ".json"


def _print_benchmark(tel: ScanTelemetry) -> None:
    """Print a detailed performance table to stdout."""
    bar = bold_divider(_BAR_WIDTH)
    sep = thin_divider(_BAR_WIDTH)
    print()
    print(bar)
    print("  Benchmark Summary")
    print(bar)
    dur = fmt_duration(tel.total_duration_seconds) if tel.total_duration_seconds else "—"
    crawl_dur = (
        fmt_duration(tel.crawl_duration_seconds) if tel.crawl_duration_seconds else "—"
    )
    pps = f"{tel.pages_per_second:.2f}" if tel.pages_per_second > 0 else "—"
    print(f"  Duration:      {dur}  (crawl: {crawl_dur})")
    print(f"  Throughput:    {tel.pages_crawled} pages  @  {pps} pages/sec")
    print(sep)
    print(
        f"  Requests:      {tel.total_requests} total"
        f"  |  {tel.successful_requests} success"
        f"  |  {tel.failed_requests} failed"
        f"  |  {tel.retried_requests} retried"
        f"  |  {tel.skipped_requests} skipped"
    )
    if tel.avg_request_ms > 0:
        print(f"  Avg resp time: {tel.avg_request_ms:.1f} ms")
    print(sep)
    slowest = tel.slowest_engines(5)
    if slowest:
        print(f"  {'Slowest Engines':<28} {'Duration':>10}  {'Findings':>8}")
        print(f"  {'-'*28} {'-'*10}  {'-'*8}")
        for name, ms in slowest:
            fcount = tel.findings_per_engine.get(name, 0)
            print(f"  {name:<28} {ms:>9.1f}ms  {fcount:>8}")
    print(bar)


def _print_startup_banner(url: str, profile_name: str, profile_desc: str) -> None:
    bar = bold_divider(_BAR_WIDTH)
    print(bar)
    print("  WebHound — Passive Security Scanner")
    print(bar)
    print(f"  Target  : {fmt_url(url, _BAR_WIDTH - 12)}")
    print(f"  Profile : {profile_name}  —  {profile_desc}")
    print(bar)
    print()


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def _build_session_context(args: argparse.Namespace) -> SessionContext | None:
    """Assemble a SessionContext from CLI flags, or return None when unused."""
    contexts: list[SessionContext] = []

    if args.session_file:
        try:
            contexts.append(SessionContext.from_file(args.session_file))
        except (ValueError, OSError) as exc:
            print(f"  [session] ERROR loading session file: {exc}", file=sys.stderr)
            sys.exit(1)

    headers: dict[str, str] = {}
    for raw in (args.headers or []):
        try:
            name, value = parse_header(raw)
            headers[name] = value
        except ValueError as exc:
            print(f"  [session] ERROR in --header: {exc}", file=sys.stderr)
            sys.exit(1)

    cookies: dict[str, str] = {}
    for raw in (args.cookies or []):
        try:
            name, value = parse_cookie(raw)
            cookies[name] = value
        except ValueError as exc:
            print(f"  [session] ERROR in --cookie: {exc}", file=sys.stderr)
            sys.exit(1)

    if headers or cookies:
        contexts.append(SessionContext(headers=headers, cookies=cookies))

    if args.bearer_token_env:
        try:
            contexts.append(SessionContext.from_env(args.bearer_token_env))
        except ValueError as exc:
            print(f"  [session] ERROR loading bearer token: {exc}", file=sys.stderr)
            sys.exit(1)

    if not contexts:
        return None
    ctx = SessionContext.merge(*contexts)
    return ctx if not ctx.is_empty else None


def _print_session_warning(ctx: SessionContext) -> None:
    """Warn the user that authenticated scanning is active."""
    bar = bold_divider(_BAR_WIDTH)
    print(bar)
    print("  *** AUTHENTICATED SCAN — session context active ***")
    print(f"  Custom headers : {ctx.header_count}")
    print(f"  Custom cookies : {ctx.cookie_count}")
    print(f"  Bearer token   : {'<set>' if ctx._bearer_token else 'no'}")  # noqa: SLF001
    print("  Secrets are NEVER included in scan reports or logs.")
    print(bar)
    print()


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


async def _run(args: argparse.Namespace) -> int:
    profile = get_profile(args.profile)
    options = profile.to_scan_options()

    store = BaselineStore(args.baseline_store) if args.baseline_store else BaselineStore()

    previous_baseline = None
    baseline_id: str | None = None

    if args.use_latest_baseline:
        previous_baseline = store.get_latest_baseline(args.url)
        if previous_baseline is None:
            print(f"  [baseline] No saved baseline for {args.url} — running without comparison.")
        else:
            baseline_id = previous_baseline.scan_id
            print(
                f"  [baseline] Loaded scan {previous_baseline.scan_id[:8]}…"
                f"  ({previous_baseline.page_count} pages)"
            )

    session_ctx = _build_session_context(args)
    if session_ctx is not None:
        _print_session_warning(session_ctx)

    _print_startup_banner(args.url, profile.name, profile.description)

    target = Target.from_url(args.url, scan_options=options)
    scanner = Scanner(target, previous_baseline=previous_baseline, session_context=session_ctx)

    result = await scanner.scan()

    # ------------------------------------------------------------------
    # WADE baseline persistence
    # ------------------------------------------------------------------
    if args.save_baseline and scanner.current_baseline is not None:
        saved_path = store.save_baseline(scanner.current_baseline)
        print(f"\n  [baseline] Saved → {saved_path}")

    # ------------------------------------------------------------------
    # Console summary (always printed)
    # ------------------------------------------------------------------
    print()
    print(SummaryBuilder().build(result))

    # ------------------------------------------------------------------
    # Report file(s)
    # ------------------------------------------------------------------
    output_dir = Path(args.output_dir) if args.output_dir else _REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = _report_stem(args.url, profile.name)
    formats = _resolve_formats(getattr(args, "formats", None))

    written: list[Path] = []

    if "json" in formats:
        path = output_dir / f"{stem}.json"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(
                JsonReport().build(result, profile_name=profile.name, baseline_id=baseline_id),
                fh,
                indent=2,
                default=str,
            )
        written.append(path)

    if "sarif" in formats:
        path = output_dir / f"{stem}.sarif"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(
                SarifReport().build(result, profile_name=profile.name),
                fh,
                indent=2,
                default=str,
            )
        written.append(path)

    if "csv" in formats:
        path = output_dir / f"{stem}.csv"
        path.write_text(CsvReport().build(result), encoding="utf-8")
        written.append(path)

    if "markdown" in formats:
        path = output_dir / f"{stem}.md"
        path.write_text(
            MarkdownReport().build(
                result, profile_name=profile.name, baseline_id=baseline_id
            ),
            encoding="utf-8",
        )
        written.append(path)

    risk_score = result.metadata.get("risk_score", "—")
    risk_level = result.metadata.get("risk_level", "unknown")
    print(f"\n  Risk: {fmt_risk(risk_score, risk_level)}")
    for p in written:
        print(f"  Report: {p}")
    print(bold_divider(_BAR_WIDTH))

    if args.benchmark:
        _print_benchmark(ScanTelemetry.from_result(result))

    return 1 if result.status.value == "failed" else 0


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
