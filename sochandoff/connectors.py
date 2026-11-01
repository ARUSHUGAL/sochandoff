"""Pull open cases straight from a SIEM / case platform.

Each connector turns the platform's own records into sochandoff case dicts,
which then go through the same validation as a file.

Credentials come from environment variables ONLY, never from CLI flags, so
they do not land in shell history or process listings.

Connectors:
  thehive  — TheHive 5 cases + observables     (SOCHANDOFF_THEHIVE_URL / _KEY)
  wazuh    — Wazuh indexer alerts, grouped     (SOCHANDOFF_WAZUH_URL / _USER / _PASS)

Network access goes through one ``fetch`` function so tests can swap in fakes.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

Fetch = Callable[[str, dict, bytes | None], object]


class ConnectorError(RuntimeError):
    pass


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConnectorError(f"set the {name} environment variable")
    return value


def http_fetch(url: str, headers: dict, body: bytes | None, verify: bool = True) -> object:
    """POST/GET JSON. Raises ConnectorError with a readable message on failure."""
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method="POST" if body is not None else "GET")
    ctx = None if verify else ssl._create_unverified_context()  # noqa: S323 (opt-in only)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        raise ConnectorError(f"{url} -> HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ConnectorError(f"could not reach {url}: {exc}") from exc


def _ms_to_iso(ms: object) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------- TheHive

# TheHive severity: 1=low 2=medium 3=high 4=critical
_HIVE_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "critical"}
# TheHive 5 status / stage -> sochandoff status
_HIVE_STATUS = {
    "new": "new",
    "inprogress": "investigating",
    "indeterminate": "investigating",
    "resolved": "closed",
    "truepositive": "closed",
    "falsepositive": "closed",
    "duplicated": "closed",
    "other": "closed",
}


def thehive_cases(fetch: Fetch | None = None, verify: bool = True) -> list[dict]:
    """Open TheHive 5 cases, with observables mapped to IOCs."""
    base = _env("SOCHANDOFF_THEHIVE_URL").rstrip("/")
    key = _env("SOCHANDOFF_THEHIVE_KEY")
    fetch = fetch or (lambda u, h, b: http_fetch(u, h, b, verify))
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    query = {"query": [
        {"_name": "listCase"},
        {"_name": "filter", "_ne": {"_field": "stage", "_value": "Closed"}},
        {"_name": "sort", "_fields": [{"_updatedAt": "desc"}]},
        {"_name": "page", "from": 0, "to": 500},
    ]}
    rows = fetch(f"{base}/api/v1/query?name=cases", headers, json.dumps(query).encode())
    if not isinstance(rows, list):
        raise ConnectorError("TheHive returned an unexpected response")

    cases = []
    for row in rows:
        case_id = row.get("_id", "")
        obs_q = {"query": [{"_name": "getCase", "idOrName": case_id}, {"_name": "observables"}]}
        try:
            observables = fetch(f"{base}/api/v1/query?name=observables", headers,
                                json.dumps(obs_q).encode()) or []
        except ConnectorError:
            observables = []  # a case without observables still gets handed off
        iocs = [o["data"] for o in observables
                if isinstance(o, dict) and o.get("data")
                and o.get("dataType") in ("ip", "domain", "hash", "fqdn", "url")]
        status = str(row.get("status", "New")).replace(" ", "").lower()
        assignee = row.get("assignee") or "unassigned"
        cases.append({
            "id": f"HIVE-{row.get('number', case_id)}",
            "title": row.get("title", "(untitled)"),
            "severity": _HIVE_SEVERITY.get(row.get("severity"), "medium"),
            "status": _HIVE_STATUS.get(status, "investigating"),
            "opened_at": _ms_to_iso(row.get("startDate") or row.get("_createdAt")),
            "last_update": _ms_to_iso(row.get("_updatedAt") or row.get("_createdAt")),
            "assignee": assignee,
            "watch": bool(row.get("flag", False)),
            "acknowledged": assignee != "unassigned",
            "tags": list(row.get("tags") or []),
            "iocs": iocs,
            "notes": (row.get("summary") or "")[:200],
        })
    return cases


# ----------------------------------------------------------------------- Wazuh

def _wazuh_severity(level: int) -> str:
    # Wazuh rule levels run 0-15.
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def wazuh_cases(
    fetch: Fetch | None = None,
    verify: bool = True,
    hours: int = 24,
    min_level: int = 7,
) -> list[dict]:
    """Recent Wazuh alerts, grouped into one case per (rule, agent).

    Wazuh has alerts, not cases. Grouping turns 300 repeats of the same rule on
    the same host into ONE line the next shift can act on.
    """
    base = _env("SOCHANDOFF_WAZUH_URL").rstrip("/")
    user = _env("SOCHANDOFF_WAZUH_USER")
    password = _env("SOCHANDOFF_WAZUH_PASS")
    fetch = fetch or (lambda u, h, b: http_fetch(u, h, b, verify))
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    query = {
        "size": 1000,
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }
    result = fetch(f"{base}/wazuh-alerts-*/_search", headers, json.dumps(query).encode())
    hits = (result or {}).get("hits", {}).get("hits", []) if isinstance(result, dict) else []

    groups: dict[tuple, dict] = {}
    for hit in hits:
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {}).get("name", "unknown-host")
        key = (rule.get("id"), agent)
        ts = src.get("timestamp", "")
        data = src.get("data", {})
        iocs = {v for v in (data.get("srcip"), data.get("dstip")) if v}
        g = groups.get(key)
        if g is None:
            groups[key] = g = {
                "id": f"WAZUH-{rule.get('id', '?')}-{agent}",
                "title": f"{rule.get('description', 'Wazuh alert')} on {agent}",
                "severity": _wazuh_severity(int(rule.get("level", 0))),
                "status": "new",
                "opened_at": ts,
                "last_update": ts,
                "assignee": "unassigned",
                "acknowledged": False,
                "tags": list(rule.get("groups") or []),
                "iocs": [],
                "_count": 0,
            }
        g["_count"] += 1
        g["opened_at"] = min(g["opened_at"], ts) if ts else g["opened_at"]
        g["last_update"] = max(g["last_update"], ts) if ts else g["last_update"]
        g["iocs"] = sorted(set(g["iocs"]) | iocs)

    cases = []
    for g in groups.values():
        count = g.pop("_count")
        g["notes"] = f"{count} alert(s) grouped"
        # Wazuh timestamps look like 2026-10-31T08:05:00.123+0000; normalize.
        for k in ("opened_at", "last_update"):
            ts = g[k]
            if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":
                g[k] = ts[:-2] + ":" + ts[-2:]
        cases.append(g)
    return cases


CONNECTORS = {
    "thehive": thehive_cases,
    "wazuh": wazuh_cases,
}
