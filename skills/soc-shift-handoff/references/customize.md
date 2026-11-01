# Customizing sochandoff

## Config file

Path: `~/.sochandoff/config.toml` (or pass `--config PATH`). Every key is optional.

```toml
[thresholds]
stale_hours = 8          # no update for longer than this = stale
max_shifts_open = 3      # open across this many shifts = drifting

[memory]
path = "~/.sochandoff/memory.json"   # point at a shared folder for team memory
shift_gap_hours = 6      # re-runs closer than this = same shift

[intel]
live = false             # true = AbuseIPDB live (needs SOCHANDOFF_ABUSEIPDB_KEY)
feed = "~/team_intel.json"
```

Ask the user what their shift length is. A 12-hour shift team usually wants
`stale_hours = 12` and `shift_gap_hours = 10`.

Before editing an existing config, read it and show the change.

## Custom intel feed

A JSON object keyed by lowercase IOC:

```json
{
  "203.0.113.9": {"malicious": true, "score": 90, "summary": "seen in our 2026-10 incident", "source": "team-feed"},
  "evil-login.com": {"malicious": true, "score": 80, "summary": "phishing domain", "source": "team-feed"}
}
```

Score 50+ or `malicious: true` shows as a hit. Point `[intel] feed` at it.

## Environment variables

| Variable | Used by |
|----------|---------|
| `SOCHANDOFF_THEHIVE_URL`, `SOCHANDOFF_THEHIVE_KEY` | `--from thehive` |
| `SOCHANDOFF_WAZUH_URL`, `SOCHANDOFF_WAZUH_USER`, `SOCHANDOFF_WAZUH_PASS` | `--from wazuh` (indexer, port 9200) |
| `SOCHANDOFF_ABUSEIPDB_KEY` | `--live-intel` |

Tell the user to set these in their shell profile or secret manager. Never
write their values into any file yourself.

## Adding a connector

Connectors live in `sochandoff/connectors.py` in a clone of the repo. A connector
is one function that returns a list of case dicts (fields in
`input-format.md`), registered in `CONNECTORS`:

```python
def splunk_cases(fetch=None, verify=True) -> list[dict]:
    base = _env("SOCHANDOFF_SPLUNK_URL").rstrip("/")
    token = _env("SOCHANDOFF_SPLUNK_TOKEN")
    fetch = fetch or (lambda u, h, b: http_fetch(u, h, b, verify))
    ...
    return cases

CONNECTORS["splunk"] = splunk_cases
```

Rules for new connectors:
- Credentials from `_env(...)` only.
- All network calls through `fetch`, so tests can pass a fake.
- Add a test in `tests/test_connectors.py` with a fake `fetch`. No real network.
- If `--from NAME` needs its own options, add them in `cli.py`.
- Run `pytest -q` before saying it works.

If the user would rather not fork, write a small converter script instead
(see `input-format.md`) and feed its output file to sochandoff.
