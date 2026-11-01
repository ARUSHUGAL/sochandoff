"""Config file: ~/.sochandoff/config.toml (or --config PATH).

Everything is optional. Secrets never go here; they come from env vars.

    [thresholds]
    stale_hours = 8
    max_shifts_open = 3

    [memory]
    path = "~/.sochandoff/memory.json"
    shift_gap_hours = 6

    [intel]
    live = false              # true = call AbuseIPDB (needs SOCHANDOFF_ABUSEIPDB_KEY)
    feed = "/path/to/your_feed.json"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = Path.home() / ".sochandoff" / "config.toml"


@dataclass
class Config:
    stale_hours: float = 8.0
    max_shifts_open: int = 3
    memory_path: str | None = None
    shift_gap_hours: float = 6.0
    intel_live: bool = False
    intel_feed: str | None = None


def load_config(path: str | Path | None = None) -> Config:
    """Read the config. A missing default file is fine; a missing --config is not."""
    explicit = path is not None
    p = Path(path).expanduser() if path else DEFAULT_PATH
    if not p.exists():
        if explicit:
            raise FileNotFoundError(f"config not found: {p}")
        return Config()
    try:
        data = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"bad config {p}: {exc}") from exc

    th = data.get("thresholds", {})
    mem = data.get("memory", {})
    intel = data.get("intel", {})
    return Config(
        stale_hours=float(th.get("stale_hours", 8.0)),
        max_shifts_open=int(th.get("max_shifts_open", 3)),
        memory_path=str(Path(mem["path"]).expanduser()) if mem.get("path") else None,
        shift_gap_hours=float(mem.get("shift_gap_hours", 6.0)),
        intel_live=bool(intel.get("live", False)),
        intel_feed=str(Path(intel["feed"]).expanduser()) if intel.get("feed") else None,
    )
