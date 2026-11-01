"""Redact mode: swap sensitive values for tokens before output leaves the box.

Use it when an AI agent reads the handoff. The agent sees `IP-3` and `USER-1`,
never the real IP or analyst name. The token map stays on this machine
(~/.sochandoff/redact-map.json, mode 600), so `--reveal` can turn a briefing
written with tokens back into the real values, locally.

What gets redacted:
  - every IOC and assignee on the cases (exact match, anywhere in the text)
  - anything that looks like an IPv4/IPv6 address, email, file hash or domain
  - your own patterns, e.g. hostnames:  [redact] patterns = ['\\bWS-\\d+\\b']

Intel is looked up BEFORE redaction, so scores stay correct.
Limits: free text like "the HR laptop" is not a pattern and stays as written.
Add a pattern for anything your team names in a fixed format.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .model import Case

DEFAULT_MAP = Path.home() / ".sochandoff" / "redact-map.json"

# Order matters: emails before domains, hashes before nothing else needs it.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("HASH", re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")),
    ("IP", re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")),
    # IPv6: full 8 groups, or a "::" form. Times like 21:56:22 never match.
    ("IP", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
                      r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?")),
    ("DOMAIN", re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|co|info|biz|xyz|ru|cn|top|"
                          r"site|online|app|dev|edu|gov|us|uk|de|fr|in|local|corp|lan|internal)\b",
                          re.I)),
]
TOKEN_RE = re.compile(r"\b(?:IP|DOMAIN|HASH|EMAIL|USER|HOST|ID)-\d+\b")
NOT_SECRET = {"unassigned"}


class Redactor:
    def __init__(self, map_path: str | Path | None = None, extra_patterns: list[str] | None = None):
        self.map_path = Path(map_path) if map_path else DEFAULT_MAP
        self.forward: dict[str, str] = {}   # "KIND:value-lowercased" -> token
        self.original: dict[str, str] = {}  # token -> value as first seen
        try:
            saved = json.loads(self.map_path.read_text())
            self.forward = saved.get("forward", {})
            self.original = saved.get("original", {})
        except (OSError, ValueError):
            pass
        self.counts: dict[str, int] = {}
        for token in self.forward.values():
            kind, _, n = token.rpartition("-")
            self.counts[kind] = max(self.counts.get(kind, 0), int(n))
        self.custom = [("HOST", re.compile(p)) for p in (extra_patterns or [])]

    def token(self, kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in self.forward:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.forward[key] = f"{kind}-{self.counts[kind]}"
            self.original[self.forward[key]] = value
        return self.forward[key]

    def learn(self, cases: list[Case]) -> None:
        """Pre-register exact values from the cases."""
        from .enrich import classify_ioc

        for c in cases:
            for ioc in c.iocs:
                kind = {"ip": "IP", "domain": "DOMAIN", "hash": "HASH"}.get(classify_ioc(ioc), "ID")
                self.token(kind, ioc)
            if c.assignee and c.assignee.lower() not in NOT_SECRET:
                self.token("USER", c.assignee)

    def redact(self, text: str) -> str:
        # 1. exact known values, longest first so "a.patel@x" beats "a.patel"
        known = sorted(((k.split(":", 1)[1], v) for k, v in self.forward.items()),
                       key=lambda kv: len(kv[0]), reverse=True)
        for value, token in known:
            if value:
                text = re.sub(rf"(?<![\w.-]){re.escape(value)}(?![\w-])", token, text, flags=re.I)
        # 2. custom patterns, then built-in shapes
        for kind, pattern in self.custom + PATTERNS:
            text = pattern.sub(lambda m, k=kind: m.group(0) if TOKEN_RE.fullmatch(m.group(0))
                               else self.token(k, m.group(0)), text)
        return text

    def save(self) -> None:
        self.map_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.map_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"forward": self.forward, "original": self.original}, fh, indent=2)
        tmp.replace(self.map_path)


def reveal(text: str, map_path: str | Path | None = None) -> str:
    """Turn tokens back into real values. Runs locally only."""
    p = Path(map_path) if map_path else DEFAULT_MAP
    try:
        back = json.loads(p.read_text()).get("original", {})
    except (OSError, ValueError):
        raise FileNotFoundError(f"no redact map at {p}") from None
    return TOKEN_RE.sub(lambda m: back.get(m.group(0), m.group(0)), text)
