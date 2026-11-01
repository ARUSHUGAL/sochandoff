"""Connector tests use fake fetch functions — no network, no real SIEM."""

import json

import pytest

from sochandoff.connectors import ConnectorError, thehive_cases, wazuh_cases
from sochandoff.loaders import validate


def test_thehive_maps_cases_and_observables(monkeypatch):
    monkeypatch.setenv("SOCHANDOFF_THEHIVE_URL", "https://hive.example")
    monkeypatch.setenv("SOCHANDOFF_THEHIVE_KEY", "k")
    calls = []

    def fake(url, headers, body):
        calls.append((url, headers, json.loads(body)))
        if "name=cases" in url:
            return [{
                "_id": "~1", "number": 7, "title": "Phish", "severity": 3,
                "status": "InProgress", "startDate": 1761890400000,
                "_updatedAt": 1761894000000, "assignee": "maya", "flag": True,
                "tags": ["phishing"],
            }]
        return [{"dataType": "ip", "data": "194.26.135.12"},
                {"dataType": "mail", "data": "x@y.z"}]

    raw = thehive_cases(fetch=fake)
    case = validate(raw)[0]
    assert case.id == "HIVE-7"
    assert case.severity == "high"
    assert case.status == "investigating"
    assert case.watch is True
    assert case.iocs == ["194.26.135.12"]
    assert calls[0][1]["Authorization"] == "Bearer k"


def test_thehive_needs_env(monkeypatch):
    monkeypatch.delenv("SOCHANDOFF_THEHIVE_URL", raising=False)
    with pytest.raises(ConnectorError, match="SOCHANDOFF_THEHIVE_URL"):
        thehive_cases(fetch=lambda *a: [])


def test_wazuh_groups_alerts(monkeypatch):
    monkeypatch.setenv("SOCHANDOFF_WAZUH_URL", "https://wazuh.example:9200")
    monkeypatch.setenv("SOCHANDOFF_WAZUH_USER", "u")
    monkeypatch.setenv("SOCHANDOFF_WAZUH_PASS", "p")

    def alert(ts, ip):
        return {"_source": {
            "timestamp": ts,
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force",
                     "groups": ["authentication_failures"]},
            "agent": {"name": "web-01"},
            "data": {"srcip": ip},
        }}

    def fake(url, headers, body):
        assert url.endswith("/wazuh-alerts-*/_search")
        return {"hits": {"hits": [
            alert("2026-10-31T08:05:00.000+0000", "45.142.212.61"),
            alert("2026-10-31T08:01:00.000+0000", "45.142.212.61"),
            alert("2026-10-31T07:55:00.000+0000", "45.142.212.62"),
        ]}}

    cases = validate(wazuh_cases(fetch=fake))
    assert len(cases) == 1  # three alerts -> one case
    c = cases[0]
    assert c.severity == "high"
    assert c.notes == "3 alert(s) grouped"
    assert c.iocs == ["45.142.212.61", "45.142.212.62"]
    assert c.opened_at.startswith("2026-10-31T07:55")
