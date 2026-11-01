"""Free, keyless threat-intel feeds, downloaded to disk and checked offline.

`sochandoff --update-feeds` pulls them into ~/.sochandoff/feeds/. Lookups then
run locally, so case data never leaves the machine just to check an IP.

Every feed here was checked to work without an API key (Nov 2026). abuse.ch's
URLhaus and ThreatFox bulk exports now need a key and are not included.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

DEFAULT_DIR = Path.home() / ".sochandoff" / "feeds"
STALE_DAYS = 7


@dataclass(frozen=True)
class FeedSpec:
    name: str
    url: str
    kind: str        # "ip" exact, "cidr" networks, "domain" from URLs, "feodo" json
    score: int
    summary: str     # may use {extra}


FEEDS: dict[str, FeedSpec] = {f.name: f for f in [
    FeedSpec("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
             "feodo", 95, "Feodo Tracker: {extra} botnet C2"),
    FeedSpec("spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt",
             "cidr", 90, "Spamhaus DROP: hijacked or criminal netblock"),
    FeedSpec("openphish", "https://openphish.com/feed.txt",
             "domain", 90, "OpenPhish: hosts an active phishing page"),
    FeedSpec("et-compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
             "ip", 75, "Emerging Threats: known compromised host"),
    FeedSpec("cins", "https://cinsscore.com/list/ci-badguys.txt",
             "ip", 70, "CINS Army: poor-reputation scanner"),
    FeedSpec("blocklist-de", "https://lists.blocklist.de/lists/all.txt",
             "ip", 65, "blocklist.de: reported attacker (SSH, mail or web)"),
]}

_IP_LINE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*(?:[#;].*)?$")


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https feed: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "sochandoff-feeds"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310
        return resp.read()


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse(spec: FeedSpec, raw: bytes) -> dict:
    """Turn a raw feed into {"exact": {ioc: extra}, "cidr": [[net, extra]]}."""
    text = raw.decode("utf-8", errors="replace")
    exact: dict[str, str] = {}
    cidr: list[list[str]] = []
    if spec.kind == "feodo":
        for row in json.loads(text):
            ip = str(row.get("ip_address", "")).strip()
            if _valid_ip(ip):
                exact[ip] = row.get("malware") or "unknown"
    elif spec.kind == "ip":
        for line in text.splitlines():
            m = _IP_LINE.match(line)
            if m and _valid_ip(m.group(1)):
                exact[m.group(1)] = ""
    elif spec.kind == "cidr":
        for line in text.splitlines():
            line = line.split(";")[0].strip()
            if not line or line.startswith("#"):
                continue
            try:
                cidr.append([str(ipaddress.ip_network(line, strict=False)), ""])
            except ValueError:
                continue
    elif spec.kind == "domain":
        for line in text.splitlines():
            host = (urlparse(line.strip()).hostname or "").lower()
            if host and not _valid_ip(host):
                exact[host] = ""
    return {"exact": exact, "cidr": cidr}


def update_feeds(
    directory: str | Path | None = None,
    names: list[str] | None = None,
    get: Callable[[str], bytes] = _get,
) -> dict[str, str]:
    """Download feeds. Returns {name: "N entries" or "error: ..."}. Never raises."""
    out_dir = Path(directory or DEFAULT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {}
    for name in names or list(FEEDS):
        spec = FEEDS.get(name)
        if spec is None:
            report[name] = "error: unknown feed"
            continue
        try:
            data = parse(spec, get(spec.url))
        except Exception as exc:  # one bad feed must not stop the others
            report[name] = f"error: {exc}"
            continue
        count = len(data["exact"]) + len(data["cidr"])
        if count == 0:
            report[name] = "error: feed was empty, kept the old copy"
            continue
        doc = {"name": name, "url": spec.url, "score": spec.score, "summary": spec.summary,
               "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"), **data}
        tmp = out_dir / f".{name}.json.tmp"
        tmp.write_text(json.dumps(doc))
        tmp.replace(out_dir / f"{name}.json")
        report[name] = f"{count} entries"
    return report


@dataclass
class FeedHit:
    feed: str
    score: int
    summary: str


class FeedIndex:
    """All downloaded feeds, loaded once, searched offline."""

    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory or DEFAULT_DIR)
        self.exact: dict[str, list[FeedHit]] = {}
        self.cidr: list[tuple[ipaddress._BaseNetwork, FeedHit]] = []
        self.stale: list[str] = []
        self.loaded: list[str] = []
        if not self.directory.is_dir():
            return
        now = datetime.now(timezone.utc)
        for path in sorted(self.directory.glob("*.json")):
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            name, score, tmpl = doc.get("name", path.stem), int(doc.get("score", 50)), doc.get("summary", "")
            self.loaded.append(name)
            try:
                age = now - datetime.fromisoformat(doc.get("updated", ""))
                if age.days >= STALE_DAYS:
                    self.stale.append(f"{name} ({age.days}d old)")
            except ValueError:
                self.stale.append(f"{name} (unknown age)")
            for ioc, extra in doc.get("exact", {}).items():
                self.exact.setdefault(ioc.lower(), []).append(
                    FeedHit(name, score, tmpl.format(extra=extra or "known")))
            for net, extra in doc.get("cidr", []):
                try:
                    self.cidr.append((ipaddress.ip_network(net),
                                      FeedHit(name, score, tmpl.format(extra=extra or "known"))))
                except ValueError:
                    continue

    def hits(self, ioc: str) -> list[FeedHit]:
        key = ioc.strip().lower()
        found = list(self.exact.get(key, []))
        if _valid_ip(key):
            ip = ipaddress.ip_address(key)
            found += [hit for net, hit in self.cidr if ip.version == net.version and ip in net]
        return sorted(found, key=lambda h: h.score, reverse=True)
