#!/usr/bin/env python3
"""Fill a fresh local TheHive 5 lab with realistic SOC cases.

Creates an org "soc-lab", an analyst user with an API key, 8 cases with
observables, and closes 1 case. Writes the analyst's URL and key to
~/.sochandoff/lab.env (mode 600) so sochandoff can connect.

Uses only the local lab's default admin login. Never run this against a
real TheHive.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

URL = os.environ.get("LAB_THEHIVE_URL", "http://127.0.0.1:9000")
ADMIN = ("admin@thehive.local", "secret")  # TheHive 5 default, lab only
ORG = "soc-lab"
ANALYST = "analyst@soc-lab.local"

if not URL.startswith(("http://127.0.0.1", "http://localhost")):
    sys.exit("refusing: seed.py only runs against a local lab")

DAY = 24 * 3600 * 1000
NOW = int(time.time() * 1000)

CASES = [
    # title, severity(1-4), flag, tags, observables, hours_ago_started, assign
    ("Phishing: credential-harvest email to finance", 3, True, ["phishing", "email"],
     [("ip", "194.26.135.12"), ("domain", "finance-secure-login.com")], 40, False),
    ("Suspicious PowerShell on HR laptop HR-LT-044", 4, True, ["malware", "edr"],
     [("hash", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")], 6, True),
    ("Brute force against VPN portal", 3, False, ["bruteforce", "vpn"],
     [("ip", "45.142.212.61")], 3, False),
    ("Impossible travel: sales account j.doe", 2, False, ["identity"], [], 30, True),
    ("Unusual data egress from FS-02", 2, False, ["dlp"], [("ip", "10.0.4.22")], 70, True),
    ("Emotet C2 beacon from WS-118", 4, False, ["c2", "emotet"],
     [("ip", "50.16.16.211")], 2, False),
    ("Typosquat domain registered for our brand", 1, False, ["brand"],
     [("domain", "acme-payrol.com")], 20, True),
    ("Expired cert on public web app", 1, False, ["hygiene"], [], 90, True),
]


def call(method, path, body=None, auth=None, bearer=None):
    req = urllib.request.Request(URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    elif auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip().startswith((b"{", b"[", b'"')) else raw.decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise RuntimeError(f"{method} {path} -> {exc.code}: {detail}") from None


def wait_ready(limit=600):
    print(f"waiting for TheHive at {URL} ...", flush=True)
    start = time.time()
    while time.time() - start < limit:
        try:
            call("GET", "/api/v1/user/current", auth=ADMIN)
            print("TheHive is up")
            return
        except Exception:
            time.sleep(5)
    sys.exit("TheHive did not come up in time. Check: docker compose logs thehive")


def main():
    wait_ready()

    try:
        call("POST", "/api/v1/organisation", {"name": ORG, "description": "sochandoff lab"}, auth=ADMIN)
        print(f"created org {ORG}")
    except RuntimeError as exc:
        if "exist" not in str(exc).lower():
            raise
        print(f"org {ORG} already exists")

    try:
        call("POST", "/api/v1/user", {"login": ANALYST, "name": "Lab Analyst",
                                       "profile": "analyst", "organisation": ORG}, auth=ADMIN)
        print(f"created user {ANALYST}")
    except RuntimeError as exc:
        if "exist" not in str(exc).lower():
            raise
    key = call("POST", f"/api/v1/user/{ANALYST}/key/renew", auth=ADMIN)
    key = key.strip().strip('"') if isinstance(key, str) else key

    created = []
    for title, sev, flag, tags, obs, hours, assign in CASES:
        body = {"title": title, "description": f"Lab case: {title}", "severity": sev,
                "flag": flag, "tags": tags, "startDate": NOW - hours * 3600 * 1000}
        if assign:
            body["assignee"] = ANALYST
        case = call("POST", "/api/v1/case", body, bearer=key)
        for data_type, data in obs:
            call("POST", f"/api/v1/case/{case['_id']}/observable",
                 {"dataType": data_type, "data": data}, bearer=key)
        created.append(case)
        print(f"  case #{case.get('number')}: {title}")

    # Close the cert case so we can check closed cases are skipped.
    last = created[-1]
    call("PATCH", f"/api/v1/case/{last['_id']}",
         {"status": "TruePositive", "summary": "Cert renewed", "impactStatus": "NoImpact"},
         bearer=key)
    print(f"  closed case #{last.get('number')}")

    env = Path.home() / ".sochandoff" / "lab.env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"export SOCHANDOFF_THEHIVE_URL={URL}\nexport SOCHANDOFF_THEHIVE_KEY={key}\n")
    env.chmod(0o600)
    print(f"\nwrote {env} (mode 600). Load it with:  . {env}")


if __name__ == "__main__":
    main()
