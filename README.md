# sochandoff

**A SOC shift-handoff tool for the terminal.** Rank your open cases by risk, and never let one fall through the crack between shifts.

```
sochandoff open_cases.json
```

---

## The problem

Every 8 hours a SOC hands its open investigations to the next shift. Today that
handoff is a Slack dump or a half-filled template. When it is sloppy, the
incoming shift retraces work, or worse, an active case gets dropped. Industry
surveys put a large share of alerts as never investigated — and the handoff gap
is where many of them disappear.

There are generic shift-handover apps (for hotels, factories) and SOC handoff
*templates*, but no small, analyst-focused tool that ranks cases and actively
guards against dropped ones. `sochandoff` is that tool.

## What it does

- **Ranks open cases by risk** — severity, status, how many shifts it has been
  open, watch flags, and staleness all feed a single score. The scariest case
  is line 1.
- **Dropped-case guard** — the headline feature. Flags any open case that looks
  likely to be lost: no owner, no recent update, open across several shifts, or
  a high/critical case nobody has acknowledged. These print first.
- **Clean terminal report** — color-coded, one screen, readable at a glance.
- **Runs out of the box** — ships with sample data so you can see it work before
  wiring in your own.

## Install

### One line (curl)

```bash
curl -fsSL https://raw.githubusercontent.com/ARUSHUGAL/sochandoff/main/install.sh | sh
```

### With pip

```bash
pip install sochandoff        # once published to PyPI
# or from source:
pip install git+https://github.com/ARUSHUGAL/sochandoff.git
```

## Usage

```bash
# Use the bundled sample data
sochandoff

# Point it at your own export
sochandoff open_cases.json

# No color (for logs or piping)
sochandoff open_cases.json --no-color
```

## Input format

A JSON list of case objects. Minimal example:

```json
[
  {
    "id": "SOC-1042",
    "title": "Phishing: credential-harvest email to finance team",
    "severity": "high",
    "status": "investigating",
    "opened_at": "2026-10-30T14:00:00Z",
    "last_update": "2026-10-31T02:00:00Z",
    "assignee": "unassigned",
    "shifts_open": 4,
    "notes": "3 users clicked. Resets pending.",
    "watch": true,
    "acknowledged": false
  }
]
```

| Field | Meaning |
|-------|---------|
| `severity` | critical, high, medium, low, info |
| `status` | new, investigating, containment, monitoring, closed |
| `shifts_open` | how many shift handoffs this case has survived |
| `watch` | pin to the top as a watch item |
| `acknowledged` | has the current shift acknowledged it |

> Most SIEMs and ticketing systems (Splunk, Sentinel, TheHive, Jira) can export
> open cases to JSON. Map their fields to the ones above and pipe it in. A
> future version will add direct connectors.

## Notes on the sample data

The bundled sample uses fixed timestamps, so as time passes every sample case
reads as "stale" and gets flagged. That is expected — it is frozen demo data.
With live timestamps, only genuinely stale cases flag.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest
pytest
```

## License

MIT. Fork it, use it, make your SOC's handoff suck less.
