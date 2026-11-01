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
from .audit import write_audit
from .export import analyze, to_json, to_markdown
from .feeds import FEEDS, update_feeds
from .loaders import CaseError, load_cases, validate
from .memory import open_memory
from .redact import Redactor, reveal
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
    p.add_argument("--update-feeds", nargs="*", metavar="FEED",
                   help=f"download free threat feeds and exit ({', '.join(FEEDS)}; default all)")
    p.add_argument("--redact", action="store_true",
                   help="swap IPs, domains, hashes, emails and names for tokens (for AI agents)")
    p.add_argument("--reveal", metavar="FILE",
                   help="turn redaction tokens in FILE back into real values, locally")
    p.add_argument("--no-audit", action="store_true", help="do not write the audit log")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--no-intel", action="store_true", help="skip threat-intel enrichment")
    p.add_argument("--no-memory", action="store_true", help="skip cross-shift memory")
    p.add_argument("--version", action="version", version=f"sochandoff {__version__}")
    return p


def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def _write_private(path: str, text: str) -> None:
    """Handoffs hold case data: create output files readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")


def _emit(args, text: str) -> None:
    if args.output:
        _write_private(args.output, text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        return _err(str(exc))
    # Mutate in place so every Case sees the configured limits.
    model.THRESHOLDS.stale_hours = cfg.stale_hours
    model.THRESHOLDS.max_shifts_open = cfg.max_shifts_open
    if cfg.ca_file and not os.environ.get("SOCHANDOFF_CA_FILE"):
        os.environ["SOCHANDOFF_CA_FILE"] = cfg.ca_file

    # --- one-off modes -------------------------------------------------------
    if args.update_feeds is not None:
        report = update_feeds(cfg.feeds_dir, args.update_feeds or None)
        for name, result in report.items():
            print(f"  {name:<15} {result}")
        return 0 if all(not r.startswith("error") for r in report.values()) else 1

    if args.reveal:
        try:
            text = reveal(Path(args.reveal).read_text(), cfg.redact_map)
        except FileNotFoundError as exc:
            return _err(str(exc))
        _emit(args, text)
        return 0

    # --- normal run ----------------------------------------------------------
    if args.source and args.cases:
        return _err("give a file OR --from, not both")
    source = args.source or (args.cases and f"file:{Path(args.cases).name}") or "sample"
    redacting = args.redact or cfg.redact_always

    def audit(**event):
        if cfg.audit_enabled and not args.no_audit:
            try:
                write_audit({"source": source, "format": args.format, "output": args.output,
                             "redacted": redacting, **event}, cfg.audit_path, cfg.audit_syslog)
            except OSError as exc:
                print(f"warning: audit log not written: {exc}", file=sys.stderr)

    try:
        if args.source:
            fetch_kwargs = {"verify": not args.insecure}
            if args.source == "wazuh":
                fetch_kwargs["hours"] = args.wazuh_hours
            cases = validate(CONNECTORS[args.source](**fetch_kwargs))
        else:
            cases = load_cases(args.cases or SAMPLE)
    except FileNotFoundError:
        audit(status="error", error="file not found")
        return _err(f"file not found: {args.cases}")
    except ConnectorError as exc:
        audit(status="error", error="connector")
        return _err(f"{args.source}: {exc}")
    except CaseError as exc:
        audit(status="error", error="invalid cases", problems=len(exc.problems))
        print("error: some cases are invalid:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    feed = None
    live = False
    if not args.no_intel:
        live = args.live_intel or cfg.intel_live
        key = os.environ.get("SOCHANDOFF_ABUSEIPDB_KEY")
        if live and not key:
            print("warning: live intel needs SOCHANDOFF_ABUSEIPDB_KEY; using offline feeds",
                  file=sys.stderr)
            live = False
        feed = IntelFeed(feed_path=cfg.intel_feed, live=live, abuseipdb_key=key,
                         feeds_dir=cfg.feeds_dir, demo=source == "sample")
        if feed.index.stale:
            print(f"warning: old feeds: {', '.join(feed.index.stale)}. "
                  "Run: sochandoff --update-feeds", file=sys.stderr)
        elif not feed.index.loaded and source != "sample":
            print("note: no threat feeds yet. Run: sochandoff --update-feeds", file=sys.stderr)

    memory = None
    if not args.no_memory:
        try:
            memory = open_memory(cfg.memory_backend, cfg.memory_path, cfg.shift_gap_hours)
        except (OSError, ValueError) as exc:
            return _err(f"memory: {exc}")

    if args.format == "text":
        color = sys.stdout.isatty() and not args.no_color and not args.output and not redacting
        out = build_report(cases, use_color=color, feed=feed, memory=memory)
        data = None
    else:
        data = analyze(cases, feed, memory)
        out = to_markdown(data) if args.format == "md" else to_json(data)
        if memory is not None:
            record_run(cases, memory)

    if redacting:
        red = Redactor(cfg.redact_map, cfg.redact_patterns)
        red.learn(cases)
        out = red.redact(out)
        red.save()

    _emit(args, out)
    open_ids = [c.id for c in cases if c.is_open]
    at_risk = sum(1 for c in cases if c.is_open and c.drop_risk()[0])
    audit(status="ok", open_cases=len(open_ids), at_risk=at_risk, case_ids=open_ids,
          intel_live=live, feeds=feed.index.loaded if feed else [])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
