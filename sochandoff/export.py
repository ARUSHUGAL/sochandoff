"""Export the handoff as Markdown (paste into a ticket / wiki / Slack) or JSON
(pipe into another tool). The terminal view lives in report.py.

These renderers only READ memory. The caller records the run afterwards,
so recall always reflects prior shifts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .enrich import IntelFeed
from .memory import ShiftMemory
from .model import Case


def analyze(cases: list[Case], feed: IntelFeed | None, memory: ShiftMemory | None) -> dict:
    """Everything a renderer needs, as plain data."""
    open_cases = sorted((c for c in cases if c.is_open),
                        key=lambda c: c.risk_score(), reverse=True)
    rows = []
    for c in open_cases:
        flagged, reason = c.drop_risk()
        intel = [v for v in (feed.enrich_case(c.iocs) if feed else []) if v.is_bad]
        recalls = [r for r in (memory.recall(i) for i in c.iocs) if r.is_repeat] if memory else []
        rows.append({
            "id": c.id,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "assignee": c.assignee,
            "risk_score": c.risk_score(),
            "shifts_open": c.shifts_open,
            "hours_since_update": round(c.hours_since_update, 1),
            "watch": c.watch,
            "acknowledged": c.acknowledged,
            "at_risk": flagged,
            "at_risk_reason": reason,
            "notes": c.notes,
            "iocs": c.iocs,
            "intel": [{"ioc": v.ioc, "kind": v.kind, "score": v.score,
                       "summary": v.summary, "source": v.source} for v in intel],
            "memory": [{"ioc": r.ioc, "prior_shifts": r.seen_count,
                        "cases": r.case_ids} for r in recalls],
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "open_cases": len(rows),
        "at_risk": sum(1 for r in rows if r["at_risk"]),
        "cases": rows,
    }


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2)


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(data: dict) -> str:
    out = [
        "# SOC Shift Handoff",
        "",
        f"_Generated {data['generated_at']}_",
        "",
        f"**Open cases:** {data['open_cases']} · **At risk of being dropped:** {data['at_risk']}",
        "",
    ]
    risky = [r for r in data["cases"] if r["at_risk"]]
    if risky:
        out += ["## ⚠️ Dropped-case guard — read these first", ""]
        for r in risky:
            out.append(f"- [ ] **{r['id']}** — {_md_escape(r['title'])}  ")
            out.append(f"  why: {_md_escape(r['at_risk_reason'])} · owner: `{r['assignee']}`")
            for m in r["memory"]:
                out.append(f"  - 🧠 `{m['ioc']}` seen in {m['prior_shifts']} prior shift(s)")
            for v in r["intel"]:
                out.append(f"  - 🌐 `{v['ioc']}` — {_md_escape(v['summary'])}")
        out.append("")

    out += ["## All open cases (ranked by risk)", "",
            "| # | Severity | Case | Status | Owner | Shifts | Last update |",
            "|---|----------|------|--------|-------|--------|-------------|"]
    for n, r in enumerate(data["cases"], 1):
        flag = " 👀" if r["watch"] else ""
        out.append(
            f"| {n} | {r['severity'].upper()} | **{r['id']}** {_md_escape(r['title'])}{flag} "
            f"| {r['status']} | {r['assignee']} | {r['shifts_open']} | {r['hours_since_update']:.0f}h ago |"
        )
    out += ["", "_Tick a box when you've taken a case. Nothing gets dropped._", ""]
    return "\n".join(out)
