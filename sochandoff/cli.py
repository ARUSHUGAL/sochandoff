"""Command-line entry point for sochandoff."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .enrich import IntelFeed
from .memory import ShiftMemory
from .report import build_report, load_cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sochandoff",
        description="Build a SOC shift-handoff report from your open cases.",
    )
    parser.add_argument(
        "cases",
        nargs="?",
        help="Path to a JSON file of open cases. Omit to use the bundled sample.",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output."
    )
    parser.add_argument(
        "--no-intel",
        action="store_true",
        help="Skip threat-intel enrichment of IOCs.",
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help="Skip cross-shift memory (no recall, no recording).",
    )
    parser.add_argument(
        "--version", action="version", version=f"sochandoff {__version__}"
    )
    args = parser.parse_args(argv)

    path = args.cases
    if path is None:
        # Fall back to the bundled sample so it runs out of the box.
        path = Path(__file__).parent / "data" / "sample_cases.json"

    try:
        cases = load_cases(path)
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError) as exc:
        print(f"error: could not parse cases: {exc}", file=sys.stderr)
        return 1

    use_color = sys.stdout.isatty() and not args.no_color
    feed = None if args.no_intel else IntelFeed()
    memory = None if args.no_memory else ShiftMemory()
    print(build_report(cases, use_color=use_color, feed=feed, memory=memory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
