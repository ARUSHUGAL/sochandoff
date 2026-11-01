---
name: soc-shift-handoff
description: Build a SOC shift handoff with the sochandoff CLI. Ranks open security cases by risk, flags cases about to be dropped between shifts, checks IOCs against threat intel, and recalls attackers seen in prior shifts. Use when the user says "shift handoff", "handover", "end of shift", "what's open in the SOC", "brief the next shift", or asks to pull open cases from TheHive, Wazuh, or a JSON/CSV case export. Also use to customize sochandoff thresholds or connectors, or to automate the handoff on a schedule. Not for general incident response or writing detections.
license: MIT
compatibility: Needs Python 3.11+ and the sochandoff CLI (pip install git+https://github.com/ARUSHUGAL/sochandoff.git). Works in any agent that runs shell commands.
metadata:
  author: Arush Ugal
  version: "0.3.0"
  homepage: https://github.com/ARUSHUGAL/sochandoff
---

# SOC shift handoff

You help a SOC analyst hand open cases to the next shift so nothing gets dropped.
The `sochandoff` CLI does the scoring. You pick the source, run it, read the
result, and write a clear briefing.

## Hard rules

1. **Never print, log, echo, or store secrets.** API keys and passwords live in
   environment variables only. Check that a variable is SET, never show its value.
2. **Never put a secret in a command line, config file, or commit.**
3. **Never use `--insecure` unless the user says the server is a lab with a
   self-signed cert.** Say it is unsafe for production.
4. **Do not invent cases, IOCs, or intel.** Everything in the briefing comes
   from sochandoff's JSON output.
5. **Do not close, edit, or reassign cases in the SIEM.** This skill is read-only.
6. **Always add `--redact` when you read real case data.** You are an AI model;
   the user's real IPs, hosts and names should not reach your provider. Only skip
   it for the bundled sample, or if the user says their SOC approved it.
7. **Never read `~/.sochandoff/redact-map.json` and never print `--reveal`
   output.** Revealing is the user's job, on their machine (see Step 4).

## Step 1: Check the setup

Run `scripts/doctor.sh` from this skill's folder. It reports Python, the CLI,
the config file, and which connector variables are set (names only).

If `sochandoff` is missing, ask before installing, then run:

```bash
pip install git+https://github.com/ARUSHUGAL/sochandoff.git
```

## Step 2: Pick the source

| User has | Command |
|----------|---------|
| Nothing yet / wants a demo | `sochandoff -f json` (bundled sample) |
| A JSON or CSV export | `sochandoff PATH -f json` |
| TheHive 5 | `sochandoff --from thehive -f json` |
| Wazuh indexer | `sochandoff --from wazuh -f json` (add `--wazuh-hours N`) |
| Splunk, Sentinel, Jira, ServiceNow | Export to JSON/CSV first. See `references/input-format.md`. |

For real data, every command above gets `--redact` (rule 6), e.g.
`sochandoff --from thehive -f json --redact`.

If the output says "no threat feeds yet" or "old feeds", run
`sochandoff --update-feeds` first (free, about 40,000 known-bad IPs and
domains, checked offline). Add `--live-intel` only if
`SOCHANDOFF_ABUSEIPDB_KEY` is set and the user is fine sending IPs to AbuseIPDB.

If a connector fails with "set the ... environment variable", tell the user the
exact variable name to set in their own shell. Do not ask them to paste the value
into chat.

## Step 3: Read the JSON

Always use `-f json` for your own reading. The shape:

```json
{
  "generated_at": "...", "open_cases": 5, "at_risk": 2,
  "cases": [{
    "id": "SOC-1042", "title": "...", "severity": "high", "status": "investigating",
    "assignee": "unassigned", "risk_score": 151, "shifts_open": 4,
    "hours_since_update": 44.0, "watch": true, "acknowledged": false,
    "at_risk": true, "at_risk_reason": "open across 4 shifts; no owner assigned",
    "iocs": ["194.26.135.12"],
    "intel": [{"ioc": "194.26.135.12", "score": 92, "summary": "...", "source": "bundled-feed"}],
    "memory": [{"ioc": "194.26.135.12", "prior_shifts": 1, "cases": ["SOC-1042"]}]
  }]
}
```

`cases` is already sorted worst first. If the command exits non-zero, show the
error lines as-is. Validation errors name the row and field to fix.

## Step 4: Write the briefing

Lead with what needs a human now. Use this order:

1. **One line:** open count, at-risk count.
2. **Act now:** every case with `at_risk: true`. For each: id, title, the
   reason, the owner, and any intel or memory hit. Say plainly what to do next
   ("assign an owner", "acknowledge", "get an update").
3. **Watch:** remaining open cases, one line each.
4. **Repeat attackers:** any IOC in `memory`. These matter most.

Keep it short. The reader just walked in with coffee.

With `--redact` you see tokens like `IP-3`, `USER-1`, `HOST-2`. Keep them
exactly as written in your briefing. Save the briefing to a file, then turn the
tokens back into real values into a NEW file without printing it:

```bash
sochandoff --reveal briefing.md -o briefing.final.md
```

Tell the user to open `briefing.final.md`. Do not read it yourself.

If the user wants the plain handoff file for Slack or a ticket:

```bash
sochandoff --from thehive -f md --redact -o handoff.md
sochandoff --reveal handoff.md -o handoff.final.md
```

## Step 5: Customize (only when asked)

Read `references/customize.md`. It covers thresholds, memory, custom intel
feeds, and adding a new connector.

## Step 6: Automate (only when asked)

Read `references/automate.md`. It covers cron, posting to Slack, and running
from this agent's own scheduler.

## Gotchas

- The bundled sample has fixed dates, so every sample case looks stale. That is
  expected. Real data with fresh times flags only real problems.
- Memory is per machine by default. For a team, run on one shared host with
  `[memory] backend = "sqlite"`. Never put memory on an SMB/NFS share.
- Every run writes a line to `~/.sochandoff/audit.jsonl`. Do not pass
  `--no-audit` unless the user asks.
- Redaction catches IPs, domains, hashes, emails, IOCs, assignees and the
  team's `[redact] patterns`. Plain words like "the HR laptop" stay. If you
  spot a real-looking hostname or name in redacted output, tell the user to
  add a pattern.
- Re-running within 6 hours counts as the same shift. That is on purpose.
- The bundled intel feed is tiny (demo only). "no intel on record" means
  unknown, not clean.
