"""Load and validate cases from files (JSON or CSV).

Every problem is reported with the case's position and id, so a bad export
says exactly which row to fix instead of dumping a Python traceback.
"""

from __future__ import annotations

import csv
import json
from dataclasses import fields
from datetime import datetime
from pathlib import Path

from .model import VALID_SEVERITIES, VALID_STATUSES, Case

REQUIRED = ("id", "title", "severity", "status", "opened_at", "last_update")
KNOWN = {f.name for f in fields(Case)}
BOOL_FIELDS = {"watch", "acknowledged"}
LIST_FIELDS = {"tags", "iocs"}
INT_FIELDS = {"shifts_open"}


class CaseError(ValueError):
    """One or more cases failed validation. ``problems`` lists each one."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("\n".join(problems))


def _is_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _coerce(item: dict) -> dict:
    """Turn CSV-style strings into the right types. JSON values pass through."""
    out = {}
    for key, value in item.items():
        if key in BOOL_FIELDS and isinstance(value, str):
            value = value.strip().lower() in ("1", "true", "yes", "y")
        elif key in LIST_FIELDS and isinstance(value, str):
            # CSV lists are separated by ; or |
            value = [v.strip() for v in value.replace("|", ";").split(";") if v.strip()]
        elif key in INT_FIELDS and isinstance(value, str):
            value = int(value) if value.strip() else 0
        out[key] = value
    return out


def validate(raw: list) -> list[Case]:
    """Check every case and build Case objects, collecting ALL problems."""
    if not isinstance(raw, list):
        raise CaseError(["input must be a list of cases"])
    problems: list[str] = []
    cases: list[Case] = []
    seen_ids: set[str] = set()

    for n, item in enumerate(raw, 1):
        where = f"case #{n}"
        if not isinstance(item, dict):
            problems.append(f"{where}: must be an object, got {type(item).__name__}")
            continue
        try:
            item = _coerce(item)
        except ValueError as exc:
            problems.append(f"{where}: {exc}")
            continue
        if item.get("id"):
            where = f"case #{n} ({item['id']})"

        bad = []
        for key in REQUIRED:
            if item.get(key) in (None, ""):
                bad.append(f"missing '{key}'")
        unknown = set(item) - KNOWN
        if unknown:
            bad.append(f"unknown field(s): {', '.join(sorted(unknown))}")
        sev = str(item.get("severity", "")).lower().strip()
        if sev and sev not in VALID_SEVERITIES:
            bad.append(f"bad severity '{sev}' (use {', '.join(sorted(VALID_SEVERITIES))})")
        st = str(item.get("status", "")).lower().strip()
        if st and st not in VALID_STATUSES:
            bad.append(f"bad status '{st}' (use {', '.join(sorted(VALID_STATUSES))})")
        for key in ("opened_at", "last_update"):
            if item.get(key) and not _is_time(item[key]):
                bad.append(f"'{key}' is not an ISO 8601 time: {item[key]!r}")
        for key in LIST_FIELDS:
            if key in item and not isinstance(item[key], list):
                bad.append(f"'{key}' must be a list")
        if item.get("id") in seen_ids:
            bad.append("duplicate id")

        if bad:
            problems.append(f"{where}: " + "; ".join(bad))
            continue
        seen_ids.add(item["id"])
        cases.append(Case(**item))

    if problems:
        raise CaseError(problems)
    return cases


def load_cases(path: str | Path) -> list[Case]:
    """Load cases from a .json or .csv file."""
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="") as fh:
            rows = [
                {k: v for k, v in row.items() if k and v not in (None, "")}
                for row in csv.DictReader(fh)
            ]
        return validate(rows)
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise CaseError([f"{p.name}: not valid JSON (line {exc.lineno}, col {exc.colno})"])
    return validate(raw)
