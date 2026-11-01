# Automating the handoff

Confirm three things with the user first: when their shifts change, where the
handoff should go, and which source to pull from. Do not schedule anything that
posts to a shared channel without a yes.

## Cron (macOS / Linux)

Write the handoff 15 minutes before each shift change (06:00, 14:00, 22:00):

```cron
45 5,13,21 * * * . "$HOME/.sochandoff/env" && sochandoff --from thehive -f md -o "$HOME/handoffs/$(date +\%F-\%H).md" 2>> "$HOME/handoffs/errors.log"
```

`~/.sochandoff/env` holds the `export SOCHANDOFF_...=` lines. Tell the user to
create it and run `chmod 600 ~/.sochandoff/env`. Do not write the secrets
yourself.

Add with `crontab -e`. Show the line to the user before adding it.

## Post to Slack

Uses an incoming webhook. The URL is a secret, so keep it in
`SLACK_WEBHOOK_URL`:

```bash
sochandoff --from thehive -f md -o /tmp/handoff.md \
  && python3 -c 'import json,sys; print(json.dumps({"text": open("/tmp/handoff.md").read()}))' \
  | curl -fsS -X POST -H 'Content-Type: application/json' --data @- "$SLACK_WEBHOOK_URL"
```

Teams and Discord webhooks work the same way. Teams wants `{"text": ...}`,
Discord wants `{"content": ...}` (2000 character limit, so post the at-risk part only).

## Only alert when something is at risk

```bash
n=$(sochandoff --from thehive -f json | python3 -c 'import json,sys; print(json.load(sys.stdin)["at_risk"])')
[ "$n" -gt 0 ] && echo "$n case(s) at risk of being dropped"
```

## From the agent's own scheduler

If this agent has a scheduler (Kiro Crew cron, Codex/Claude automations), use it
to run Step 2 to Step 4 of SKILL.md at each shift change. Prefer a plain shell
job when the output is a file; it costs no model tokens.

## GitHub Actions (for lab or demo data only)

Keep real SOC case data off public CI. For a demo:

```yaml
on:
  schedule: [{cron: "45 5,13,21 * * *"}]
jobs:
  handoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install git+https://github.com/ARUSHUGAL/sochandoff.git
      - run: sochandoff -f md -o handoff.md
      - uses: actions/upload-artifact@v4
        with: {name: handoff, path: handoff.md}
```
