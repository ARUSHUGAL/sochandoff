"""Build the terminal handoff report from a list of cases."""

from __future__ import annotations

from .enrich import IntelFeed
from .loaders import load_cases  # noqa: F401  (re-exported for callers)
from .memory import ShiftMemory
from .model import Case

CYAN = "\033[36m"
MAGENTA = "\033[35m"

# ANSI colors. Disabled automatically when output is not a terminal.
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
DIM = "\033[2m"

SEVERITY_COLOR = {
    "critical": RED,
    "high": RED,
    "medium": YELLOW,
    "low": GREEN,
    "info": DIM,
}


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def _intel_lines(case, feed, use_color):
    """Return threat-intel lines for a case's IOCs. Only bad ones are shown."""
    out = []
    for verdict in feed.enrich_case(case.iocs):
        if verdict.is_bad:
            out.append(
                f"      {_c('🌐 intel', CYAN, use_color)}: "
                f"{verdict.ioc} ({verdict.kind}) — "
                f"{_c(verdict.summary, RED, use_color)}"
            )
    return out


def _memory_lines(case, memory, use_color):
    """Return cross-shift memory lines for repeat IOCs."""
    out = []
    for ioc in case.iocs:
        recall = memory.recall(ioc)
        if recall.is_repeat:
            seen = recall.seen_count
            shift_word = "shift" if seen == 1 else "shifts"
            out.append(
                f"      {_c('🧠 memory', MAGENTA, use_color)}: "
                f"{ioc} seen in {seen} prior {shift_word} "
                f"(cases: {', '.join(recall.case_ids[:3])})"
            )
    return out


def build_report(
    cases: list[Case],
    use_color: bool = True,
    feed: IntelFeed | None = None,
    memory: ShiftMemory | None = None,
) -> str:
    """Return the full handoff report as a string.

    If ``feed`` is given, each case is enriched with threat intel for its IOCs.
    If ``memory`` is given, repeat IOCs are recalled across shifts, and this
    run is recorded back into memory.
    """
    open_cases = [c for c in cases if c.is_open]
    ranked = sorted(open_cases, key=lambda c: c.risk_score(), reverse=True)

    at_risk = []
    for case in ranked:
        flagged, reason = case.drop_risk()
        if flagged:
            at_risk.append((case, reason))

    lines: list[str] = []
    bar = "=" * 60
    lines.append(_c(bar, BOLD, use_color))
    lines.append(_c("  SOC SHIFT HANDOFF", BOLD, use_color))
    lines.append(_c(bar, BOLD, use_color))
    lines.append("")
    lines.append(
        f"  Open cases: {len(open_cases)}    "
        f"At-risk of being dropped: "
        f"{_c(str(len(at_risk)), RED if at_risk else GREEN, use_color)}"
    )
    lines.append("")

    # The dropped-case guard — the headline feature. Show it first and loud.
    if at_risk:
        lines.append(_c("  ⚠  DROPPED-CASE GUARD — read these first", RED, use_color))
        lines.append("  " + "-" * 56)
        for case, reason in at_risk:
            lines.append(
                f"  {_c('!', RED, use_color)} [{case.id}] "
                f"{_c(case.title, BOLD, use_color)}"
            )
            lines.append(f"      why flagged: {_c(reason, YELLOW, use_color)}")
            lines.append(f"      owner: {case.assignee}")
            if memory is not None:
                lines.extend(_memory_lines(case, memory, use_color))
            if feed is not None:
                lines.extend(_intel_lines(case, feed, use_color))
        lines.append("")

    # Full ranked list of open cases.
    lines.append(_c("  ALL OPEN CASES (ranked by risk)", BOLD, use_color))
    lines.append("  " + "-" * 56)
    for i, case in enumerate(ranked, 1):
        sev = _c(
            f"{case.severity.upper():<8}",
            SEVERITY_COLOR.get(case.severity, ""),
            use_color,
        )
        watch = _c(" [WATCH]", YELLOW, use_color) if case.watch else ""
        ack = "" if case.acknowledged else _c(" (unack)", DIM, use_color)
        lines.append(
            f"  {i:>2}. {sev} [{case.id}] {case.title}{watch}{ack}"
        )
        lines.append(
            f"      {DIM if use_color else ''}status={case.status} "
            f"owner={case.assignee} shifts_open={case.shifts_open} "
            f"last_update={case.hours_since_update:.0f}h ago"
            f"{RESET if use_color else ''}"
        )
        if case.notes:
            lines.append(f"      note: {case.notes}")
        if memory is not None:
            lines.extend(_memory_lines(case, memory, use_color))
        if feed is not None:
            lines.extend(_intel_lines(case, feed, use_color))
    lines.append("")
    lines.append(_c(bar, BOLD, use_color))

    # Record this run's IOCs into memory AFTER building the report, so this
    # run's recall reflects only PRIOR shifts, not itself.
    if memory is not None:
        record_run(ranked, memory)

    return "\n".join(lines)


def record_run(cases: list[Case], memory: ShiftMemory) -> None:
    """Save every open case's IOCs into cross-shift memory."""
    for case in cases:
        if case.is_open:
            for ioc in case.iocs:
                memory.record(ioc, case.id)
    memory.save()
