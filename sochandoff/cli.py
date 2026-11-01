"""Command-line entry point for sochandoff."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, model
from .config import load_config
from .connectors import CONNECTORS, ConnectorError
from .enrich import IntelFeed
from .export import analyze, to_json, to_markdown
from .loaders import CaseError, load_cases, validate
from .memory import ShiftMemory
from .report import build_report, record_run

SAMPLE = Path(__file__).parent / "data" / "sample_cases.json"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sochandoff",
        description="Build a SOC shift-handoff report from your open cases.",
        epilog=(
            "examples:\n"
            "  sochandoff                         # bundled sample data\n"
            "  sochandoff cases.json              # JSON or CSV export\n"
            "  sochandoff --from thehive          # live from TheHive\n"
            "  sochandoff --from wazuh -f md -o handoff.md\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("cases", nargs="?", help="JSON or CSV file of cases (default: bundled sample)")
    p.add_argument("--from", dest="source", choices=sorted(CONNECTORS),
                   help="pull cases live from a platform instead of a file")
    p.add_argument("-f", "--format", choices=["text", "md", "json"], default="text",
                   help="output format (default: text)")
    p.add_argument("-o", "--output", help="write to this file instead of the screen")
    p.add_argument("--config", help="config file (default: ~/.sochandoff/config.toml)")
    p.add_argument("--live-intel", action="store_true",
                   help="query AbuseIPDB live (needs SOCHANDOFF_ABUSEIPDB_KEY)")
    p.add_argument("--wazuh-hours", type=int, default=24, help="Wazuh lookback window (default 24)")
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS checks for self-signed lab servers (never in prod)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--no-intel", action="store_true", help="skip threat-intel enrichment")
    p.add_argument("--no-memory", action="store_true", help="skip cross-shift memory")
    p.add_argument("--version", action="version", version=f"sochandoff {__version__}")
    return p


def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        return _err(str(exc))
    # Mutate in place so every Case sees the configured limits.
    model.THRESHOLDS.stale_hours = cfg.stale_hours
    model.THRESHOLDS.max_shifts_open = cfg.max_shifts_open

    if args.source and args.cases:
        return _err("give a file OR --from, not both")

    try:
        if args.source:
            fetch_kwargs = {"verify": not args.insecure}
            if args.source == "wazuh":
                fetch_kwargs["hours"] = args.wazuh_hours
            cases = validate(CONNECTORS[args.source](**fetch_kwargs))
        else:
            cases = load_cases(args.cases or SAMPLE)
    except FileNotFoundError:
        return _err(f"file not found: {args.cases}")
    except ConnectorError as exc:
        return _err(f"{args.source}: {exc}")
    except CaseError as exc:
        print("error: some cases are invalid:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    feed = None
    if not args.no_intel:
        live = args.live_intel or cfg.intel_live
        key = os.environ.get("SOCHANDOFF_ABUSEIPDB_KEY")
        if live and not key:
            print("warning: live intel needs SOCHANDOFF_ABUSEIPDB_KEY; using local feed",
                  file=sys.stderr)
        feed = IntelFeed(feed_path=cfg.intel_feed, live=live, abuseipdb_key=key)
    memory = None if args.no_memory else ShiftMemory(
        store_path=cfg.memory_path, shift_gap_hours=cfg.shift_gap_hours)

    if args.format == "text":
        color = sys.stdout.isatty() and not args.no_color and not args.output
        out = build_report(cases, use_color=color, feed=feed, memory=memory)
    else:
        data = analyze(cases, feed, memory)
        out = to_markdown(data) if args.format == "md" else to_json(data)
        if memory is not None:
            record_run(cases, memory)

    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
