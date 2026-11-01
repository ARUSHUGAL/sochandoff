# Security

## Reporting a problem

Email arushugal@gmail.com with "sochandoff security" in the subject. Please do
not open a public issue for a vulnerability. Expect a reply within 7 days.

## What sochandoff touches

| Data | Where it goes | Protection |
|------|---------------|------------|
| Case data from TheHive / Wazuh / files | Memory only, plus your output file | Output files are created mode 600 |
| API keys and passwords | Read from env vars | Never in flags, config, logs, or errors |
| IOCs for intel | Checked against local feed files | No case data leaves the box unless `--live-intel` is on (sends IPs only, to AbuseIPDB) |
| Cross-shift memory | `~/.sochandoff/memory.json` or a SQLite file | Mode 600 (JSON) / 660 (team SQLite) |
| Audit log | `~/.sochandoff/audit.jsonl`, optional syslog | Mode 600. Case IDs only, no titles, notes, or IOCs |
| Redaction map | `~/.sochandoff/redact-map.json` | Mode 600. Never send this file anywhere |

## Using it with AI agents

When an AI agent (Claude Code, Codex, Kiro, Freebuff) runs sochandoff, the
output goes to that agent's model provider. Many SOCs do not allow that.

- Get approval from your security team first.
- Always use `--redact`, or set `[redact] always = true`.
- Add `[redact] patterns` for your hostname and username formats.
  Free text that matches no pattern ("the HR laptop") is not redacted.
- Run `sochandoff --reveal FILE -o FILE` yourself to get the real values back.

## Hardening checklist for a team

- Run on one shared host (jump box). Use `[memory] backend = "sqlite"`.
  Do not put memory files on SMB/NFS shares.
- Make `/etc` or root-owned copies of the config if you need to stop analysts
  turning the audit log off.
- Ship `[audit] syslog = true` to your SIEM.
- Use a read-only TheHive API key / Wazuh user. sochandoff never writes back.
- Set `SOCHANDOFF_CA_FILE` for internal CAs. Never use `--insecure` outside a lab.
- Run `sochandoff --update-feeds` daily (cron). Feeds older than 7 days warn.

## CI

Every push runs the tests, `bandit` (code scan), `pip-audit` (known CVEs),
and a committed-secrets check. A weekly run catches new CVEs and dead feeds.
