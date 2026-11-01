"""Config file: ~/.sochandoff/config.toml (or --config PATH).

Everything is optional. Secrets never go here; they come from env vars.
See config.example.toml for every key.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path.home() / ".sochandoff" / "config.toml"


@dataclass
class Config:
    stale_hours: float = 8.0
    max_shifts_open: int = 3
    memory_backend: str = "json"
    memory_path: str | None = None
    shift_gap_hours: float = 6.0
    intel_live: bool = False
    intel_feed: str | None = None
    feeds_dir: str | None = None
    audit_enabled: bool = True
    audit_path: str | None = None
    audit_syslog: bool = False
    redact_always: bool = False
    redact_patterns: list[str] = field(default_factory=list)
    redact_map: str | None = None
    ca_file: str | None = None


def _path(value) -> str | None:
    return str(Path(value).expanduser()) if value else None


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

    th, mem, intel = data.get("thresholds", {}), data.get("memory", {}), data.get("intel", {})
    audit, red, tls = data.get("audit", {}), data.get("redact", {}), data.get("tls", {})
    backend = str(mem.get("backend", "json"))
    if backend not in ("json", "sqlite"):
        raise ValueError(f"bad config {p}: [memory] backend must be json or sqlite")
    patterns = red.get("patterns", [])
    if not isinstance(patterns, list):
        raise ValueError(f"bad config {p}: [redact] patterns must be a list")
    return Config(
        stale_hours=float(th.get("stale_hours", 8.0)),
        max_shifts_open=int(th.get("max_shifts_open", 3)),
        memory_backend=backend,
        memory_path=_path(mem.get("path")),
        shift_gap_hours=float(mem.get("shift_gap_hours", 6.0)),
        intel_live=bool(intel.get("live", False)),
        intel_feed=_path(intel.get("feed")),
        feeds_dir=_path(intel.get("feeds_dir")),
        audit_enabled=bool(audit.get("enabled", True)),
        audit_path=_path(audit.get("path")),
        audit_syslog=bool(audit.get("syslog", False)),
        redact_always=bool(red.get("always", False)),
        redact_patterns=[str(x) for x in patterns],
        redact_map=_path(red.get("map")),
        ca_file=_path(tls.get("ca_file")),
    )
