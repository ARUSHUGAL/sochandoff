"""Cross-shift memory.

The point: when an IOC shows up again, the handoff should say "we have seen
this attacker before." This module keeps a small local history of every IOC the
tool has reported, so later runs can recognize repeats across shifts and days.

Storage is a plain JSON file so it is inspectable and git-ignorable. No
database, no server — it just works.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Recall:
    """What memory knows about one IOC."""

    ioc: str
    seen_count: int          # how many prior shifts/runs saw it
    first_seen: str
    last_seen: str
    case_ids: list[str]

    @property
    def is_repeat(self) -> bool:
        return self.seen_count > 0


class ShiftMemory:
    def __init__(self, store_path: str | Path | None = None):
        if store_path is None:
            store_path = Path.home() / ".sochandoff" / "memory.json"
        self.path = Path(store_path)
        self._data: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (ValueError, OSError):
                self._data = {}

    def recall(self, ioc: str) -> Recall:
        """What do we remember about this IOC, BEFORE recording this run."""
        rec = self._data.get(ioc.lower())
        if not rec:
            return Recall(ioc=ioc, seen_count=0, first_seen="", last_seen="", case_ids=[])
        return Recall(
            ioc=ioc,
            seen_count=int(rec.get("seen_count", 0)),
            first_seen=rec.get("first_seen", ""),
            last_seen=rec.get("last_seen", ""),
            case_ids=list(rec.get("case_ids", [])),
        )

    def record(self, ioc: str, case_id: str) -> None:
        """Log that we saw this IOC on this run, for future recall."""
        key = ioc.lower()
        now = _now_iso()
        rec = self._data.get(key)
        if rec:
            rec["seen_count"] = int(rec.get("seen_count", 0)) + 1
            rec["last_seen"] = now
            if case_id not in rec.get("case_ids", []):
                rec.setdefault("case_ids", []).append(case_id)
        else:
            self._data[key] = {
                "seen_count": 1,
                "first_seen": now,
                "last_seen": now,
                "case_ids": [case_id],
            }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))
