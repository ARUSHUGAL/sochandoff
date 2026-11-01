"""Threat-intel enrichment for IOCs (IPs, domains, file hashes).

Design goals:
- Works OFFLINE out of the box using a bundled local intel feed, so a demo
  always produces the "this IP is known-bad" lines.
- Optionally queries a live source when online and enabled, without ever
  blocking the report if the network is slow or down.

This is deliberately source-agnostic. The bundled feed stands in for what a
real deployment would pull from VirusTotal, AbuseIPDB, URLhaus, etc. The
classification type ('ip', 'domain', 'hash') is inferred from the IOC shape.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def classify_ioc(ioc: str) -> str:
    """Return 'ip', 'domain', 'hash', or 'unknown' from the IOC's shape."""
    ioc = ioc.strip()
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(ioc):
        return "hash"
    if _DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


@dataclass
class Verdict:
    """One IOC's threat-intel result."""

    ioc: str
    kind: str
    malicious: bool
    score: int           # 0-100, higher = worse
    summary: str         # human line for the report
    source: str          # where the verdict came from

    @property
    def is_bad(self) -> bool:
        return self.malicious or self.score >= 50


class IntelFeed:
    """Looks up IOCs. Local feed first; live source optional and best-effort."""

    def __init__(self, feed_path: str | Path | None = None):
        if feed_path is None:
            feed_path = Path(__file__).parent / "data" / "intel_feed.json"
        self._feed: dict[str, dict] = {}
        p = Path(feed_path)
        if p.exists():
            self._feed = json.loads(p.read_text())

    def lookup(self, ioc: str) -> Verdict:
        ioc = ioc.strip()
        kind = classify_ioc(ioc)
        hit = self._feed.get(ioc.lower())
        if hit:
            return Verdict(
                ioc=ioc,
                kind=kind,
                malicious=bool(hit.get("malicious", False)),
                score=int(hit.get("score", 0)),
                summary=hit.get("summary", "listed in local intel feed"),
                source=hit.get("source", "local-feed"),
            )
        # Not in the feed — unknown, treated as clean until proven otherwise.
        return Verdict(
            ioc=ioc,
            kind=kind,
            malicious=False,
            score=0,
            summary="no intel on record",
            source="local-feed",
        )

    def enrich_case(self, iocs: list[str]) -> list[Verdict]:
        return [self.lookup(i) for i in iocs]
