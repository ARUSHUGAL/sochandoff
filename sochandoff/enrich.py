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

from .feeds import FeedIndex

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
    """Looks up IOCs.

    Resolution order for each IOC:
      1. the bundled/local JSON feed (always available, offline);
      2. an optional LIVE source (AbuseIPDB for IPs), used only when a key is
         provided and ``live=True`` — best-effort, never blocks the report.

    Live results are cached in-memory for the run so repeat IOCs cost one call.
    """

    # AbuseIPDB free API: scores an IP's abuse confidence 0-100.
    _ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    DEMO_FEED = Path(__file__).parent / "data" / "intel_feed.json"

    def __init__(
        self,
        feed_path: str | Path | None = None,
        live: bool = False,
        abuseipdb_key: str | None = None,
        timeout: float = 4.0,
        feeds_dir: str | Path | None = None,
        demo: bool = False,
    ):
        """
        feed_path: your team's own IOC file (config [intel] feed).
        feeds_dir: downloaded public feeds (sochandoff --update-feeds).
        demo:      also load the bundled demo list. Only for the sample data;
                   its entries are made up and must never judge real IPs.
        """
        self._feed: dict[str, dict] = {}
        for p in ([self.DEMO_FEED] if demo else []) + ([Path(feed_path)] if feed_path else []):
            if p.exists():
                self._feed.update({k.lower(): v for k, v in json.loads(p.read_text()).items()})
        self.index = FeedIndex(feeds_dir)
        self.live = live
        self.abuseipdb_key = abuseipdb_key
        self.timeout = timeout
        self._cache: dict[str, Verdict] = {}

    def _from_local(self, ioc: str, kind: str) -> Verdict | None:
        hit = self._feed.get(ioc.lower())
        if not hit:
            return None
        return Verdict(
            ioc=ioc,
            kind=kind,
            malicious=bool(hit.get("malicious", False)),
            score=int(hit.get("score", 0)),
            summary=hit.get("summary", "listed in local intel feed"),
            source=hit.get("source", "local-feed"),
        )

    def _from_feeds(self, ioc: str, kind: str) -> Verdict | None:
        hits = self.index.hits(ioc)
        if not hits:
            return None
        top = hits[0]
        more = len({h.feed for h in hits}) - 1
        extra = f" (+{more} more feed{'s' if more > 1 else ''})" if more else ""
        return Verdict(ioc=ioc, kind=kind, malicious=top.score >= 50, score=top.score,
                       summary=top.summary + extra, source=top.feed)

    def _from_abuseipdb(self, ioc: str) -> Verdict | None:
        """Live IP lookup. Returns None on any error — never raises."""
        if not (self.live and self.abuseipdb_key):
            return None
        try:
            import json as _json
            import urllib.parse
            import urllib.request

            qs = urllib.parse.urlencode({"ipAddress": ioc, "maxAgeInDays": 90})
            req = urllib.request.Request(
                f"{self._ABUSEIPDB_URL}?{qs}",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                data = _json.loads(resp.read()).get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
            country = data.get("countryCode") or "?"
            return Verdict(
                ioc=ioc,
                kind="ip",
                malicious=score >= 50,
                score=score,
                summary=(
                    f"AbuseIPDB confidence {score}%, {reports} reports, {country}"
                ),
                source="abuseipdb-live",
            )
        except Exception:
            # Network down, bad key, rate limit — fall through to local/clean.
            return None

    def lookup(self, ioc: str) -> Verdict:
        ioc = ioc.strip()
        if ioc in self._cache:
            return self._cache[ioc]
        kind = classify_ioc(ioc)

        # Live source wins when it has an answer (freshest), IPs only for now.
        verdict = None
        if kind == "ip":
            verdict = self._from_abuseipdb(ioc)
        if verdict is None:
            verdict = self._from_local(ioc, kind)
        if verdict is None:
            verdict = self._from_feeds(ioc, kind)
        if verdict is None:
            verdict = Verdict(
                ioc=ioc,
                kind=kind,
                malicious=False,
                score=0,
                summary="no intel on record",
                source="local-feed",
            )
        self._cache[ioc] = verdict
        return verdict

    def enrich_case(self, iocs: list[str]) -> list[Verdict]:
        return [self.lookup(i) for i in iocs]
