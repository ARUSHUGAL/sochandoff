"""Audit log: one JSON line per run, so a SOC lead or auditor can see who
pulled which cases, from where, and where the output went.

Case IDs are logged. Titles, notes and IOCs are NOT, so the log itself does
not become a second copy of sensitive case data.

Optional syslog copy lets a SIEM collect it like any other audit source.
"""

from __future__ import annotations

import getpass
import json
import logging
import logging.handlers
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

DEFAULT_PATH = Path.home() / ".sochandoff" / "audit.jsonl"


def _syslog_handler() -> logging.Handler | None:
    for addr in ("/var/run/syslog", "/dev/log"):
        if os.path.exists(addr):
            return logging.handlers.SysLogHandler(address=addr)
    return None


def write_audit(event: dict, path: str | Path | None = None, syslog: bool = False) -> dict:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "sochandoff",
        "version": __version__,
        "user": os.environ.get("SOCHANDOFF_ANALYST") or getpass.getuser(),
        "host": socket.gethostname(),
        **event,
    }
    p = Path(path) if path else DEFAULT_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")

    if syslog:
        handler = _syslog_handler()
        if handler is not None:
            log = logging.getLogger("sochandoff.audit")
            log.propagate = False
            log.addHandler(handler)
            log.setLevel(logging.INFO)
            log.info("sochandoff: %s", json.dumps(record, sort_keys=True))
            log.removeHandler(handler)
            handler.close()
    return record
