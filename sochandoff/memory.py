"""Cross-shift memory: "we have seen this attacker before."

Two backends, same interface (recall / record / save):

  json    one file, default ~/.sochandoff/memory.json. Writes are locked,
          merged with whatever is on disk, and swapped in atomically, so two
          analysts saving at the same moment do not wipe each other out.
  sqlite  one database file for a whole team on a shared host (jump box,
          SOC server). Uses SQLite transactions and a busy timeout.

Do not put either file on a network share (SMB/NFS): file locks there are
unreliable. Run sochandoff on one shared host instead.
"""

from __future__ import annotations

import contextlib
import fcntl
import getpass
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DIR = Path.home() / ".sochandoff"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hours_between(a: str, b: str) -> float:
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 3600


def _analyst() -> str:
    try:
        return os.environ.get("SOCHANDOFF_ANALYST") or getpass.getuser()
    except Exception:
        return "unknown"


@dataclass
class Recall:
    """What memory knows about one IOC."""

    ioc: str
    seen_count: int          # how many prior shifts saw it
    first_seen: str
    last_seen: str
    case_ids: list[str]
    last_seen_by: str = ""

    @property
    def is_repeat(self) -> bool:
        return self.seen_count > 0


def _apply(data: dict, key: str, case_id: str, now: str, gap: float, who: str) -> None:
    """One sighting. Same-shift re-runs never bump the count."""
    rec = data.get(key)
    if rec is None:
        data[key] = {"seen_count": 1, "first_seen": now, "last_seen": now,
                     "case_ids": [case_id], "last_seen_by": who}
        return
    if _hours_between(rec.get("last_seen", now), now) >= gap:
        rec["seen_count"] = int(rec.get("seen_count", 0)) + 1
    rec["last_seen"] = max(rec.get("last_seen", now), now)
    rec["last_seen_by"] = who
    if case_id not in rec.setdefault("case_ids", []):
        rec["case_ids"].append(case_id)


class ShiftMemory:
    """JSON-file backend."""

    def __init__(self, store_path: str | Path | None = None, shift_gap_hours: float = 6.0):
        self.path = Path(store_path) if store_path else DEFAULT_DIR / "memory.json"
        self.shift_gap_hours = shift_gap_hours
        self._data = self._read()
        self._pending: list[tuple[str, str, str, str]] = []

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def recall(self, ioc: str) -> Recall:
        rec = self._data.get(ioc.lower())
        if not rec:
            return Recall(ioc, 0, "", "", [])
        return Recall(ioc, int(rec.get("seen_count", 0)), rec.get("first_seen", ""),
                      rec.get("last_seen", ""), list(rec.get("case_ids", [])),
                      rec.get("last_seen_by", ""))

    def record(self, ioc: str, case_id: str, now: str | None = None) -> None:
        item = (ioc.lower(), case_id, now or _now_iso(), _analyst())
        self._pending.append(item)
        _apply(self._data, item[0], item[1], item[2], self.shift_gap_hours, item[3])

    @contextlib.contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_suffix(self.path.suffix + ".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def save(self) -> None:
        if not self._pending:
            return
        with self._locked():
            disk = self._read()  # someone else may have saved since we loaded
            for key, case_id, now, who in self._pending:
                _apply(disk, key, case_id, now, self.shift_gap_hours, who)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(disk, indent=2))
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
        self._data, self._pending = disk, []


class SqliteMemory:
    """SQLite backend for a team on one shared host."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS iocs (
        ioc TEXT PRIMARY KEY, seen_count INTEGER NOT NULL,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_seen_by TEXT);
    CREATE TABLE IF NOT EXISTS ioc_cases (
        ioc TEXT NOT NULL, case_id TEXT NOT NULL, PRIMARY KEY (ioc, case_id));
    """

    def __init__(self, store_path: str | Path | None = None, shift_gap_hours: float = 6.0):
        self.path = Path(store_path) if store_path else DEFAULT_DIR / "memory.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(self.SCHEMA)
        if new:
            # Owner + group so the SOC team group can share it; never world.
            os.chmod(self.path, 0o660)  # nosec B103
        self.shift_gap_hours = shift_gap_hours
        # Snapshot for recall, so this run only sees PRIOR shifts.
        self._snapshot = {row[0]: row for row in self.db.execute(
            "SELECT ioc, seen_count, first_seen, last_seen, last_seen_by FROM iocs")}
        self._cases: dict[str, list[str]] = {}
        for ioc, case_id in self.db.execute("SELECT ioc, case_id FROM ioc_cases"):
            self._cases.setdefault(ioc, []).append(case_id)
        self._pending: list[tuple[str, str, str, str]] = []

    def recall(self, ioc: str) -> Recall:
        row = self._snapshot.get(ioc.lower())
        if not row:
            return Recall(ioc, 0, "", "", [])
        return Recall(ioc, row[1], row[2], row[3], self._cases.get(row[0], []), row[4] or "")

    def record(self, ioc: str, case_id: str, now: str | None = None) -> None:
        self._pending.append((ioc.lower(), case_id, now or _now_iso(), _analyst()))

    def save(self) -> None:
        if not self._pending:
            return
        with self.db:  # one transaction
            self.db.execute("BEGIN IMMEDIATE")
            for key, case_id, now, who in self._pending:
                row = self.db.execute("SELECT seen_count, last_seen FROM iocs WHERE ioc=?",
                                      (key,)).fetchone()
                if row is None:
                    self.db.execute("INSERT INTO iocs VALUES (?,?,?,?,?)", (key, 1, now, now, who))
                else:
                    bump = 1 if _hours_between(row[1], now) >= self.shift_gap_hours else 0
                    self.db.execute(
                        "UPDATE iocs SET seen_count=seen_count+?, last_seen=max(last_seen, ?), "
                        "last_seen_by=? WHERE ioc=?", (bump, now, who, key))
                self.db.execute("INSERT OR IGNORE INTO ioc_cases VALUES (?,?)", (key, case_id))
        self._pending = []


def open_memory(backend: str = "json", path: str | Path | None = None, shift_gap_hours: float = 6.0):
    if backend == "sqlite":
        return SqliteMemory(path, shift_gap_hours)
    if backend == "json":
        return ShiftMemory(path, shift_gap_hours)
    raise ValueError(f"unknown memory backend '{backend}' (use json or sqlite)")
