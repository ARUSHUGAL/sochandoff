# sochandoff

**The SOC shift-handoff that doesn't suck.** Rank your open cases by risk, call out the ones about to die in a ditch, and never again hand the next shift a Slack message that just says *"few things going on, gl."*

```bash
sochandoff open_cases.json
```

![demo](assets/demo.svg)

---

## The problem (you already know it)

It's 6 AM. You've been staring at alerts for eight hours. Your brain is soup. The next analyst walks in, coffee in hand, and asks "anything I should know?" and you say:

> "uhh yeah the phishing thing is still going, and check the HR laptop, and... something about a VPN? gotta run, bye"

<img src="https://media.giphy.com/media/l0HlQXlQ3nHyLMvte/giphy.gif" width="320" alt="this is fine dog in a burning room" />

*(the handoff process at most SOCs, colorized)*

Then the phishing case sits there with no owner, nobody acknowledges it, and the attacker throws a party in your finance team's inbox. Industry surveys say a huge chunk of alerts never get investigated. A lot of them die right here, in the gap between two tired humans.

ServiceNow has your tickets. Splunk has your logs. Neither one looks the incoming shift in the eye and says **"THIS one. Start here. It's on fire."**

That's the job. That's `sochandoff`.

## What it does

<img src="https://media.giphy.com/media/3o7aCSPqXE5C6T8tBC/giphy.gif" width="260" align="right" alt="math lady confused meme" />

- **Ranks open cases by risk** so the scariest thing is line 1, not buried under a cert-expiry ticket from last Tuesday.
- **Dropped-case guard** — the star of the show. Flags any case about to fall through the crack: no owner, no recent update, open across too many shifts, or a critical nobody has acknowledged. These print **first and in red**, because subtlety is for people who aren't tired.
- **Threat-intel enrichment** 🌐 — every IP, domain, and hash gets checked. "This IP is known phishing, seen in 312 reports" hits different than a raw number.
- **Cross-shift memory** 🧠 — it *remembers*. "Hey, this exact attacker showed up two shifts ago." Your SOC finally has object permanence.
- **Runs offline out of the box** with bundled sample data, so your demo never dies on stage.

## Install

### One line (the cool way)

```bash
curl -fsSL https://raw.githubusercontent.com/ARUSHUGAL/sochandoff/main/install.sh | sh
```

<img src="https://media.giphy.com/media/26tn33aiTi1jkl6H6/giphy.gif" width="240" alt="hacker typing furiously meme" />

*(you, pretending the curl command makes you a hacker. it's fine. we all do it.)*

### With pip (the responsible way)

```bash
pip install git+https://github.com/ARUSHUGAL/sochandoff.git
```

## Usage

```bash
sochandoff                      # bundled sample data — try it right now
sochandoff open_cases.json      # your own export
sochandoff open_cases.json --no-color   # for logs / piping / goths
sochandoff --no-intel --no-memory       # back to boring mode
```

## Input format

A JSON list of cases. Export open cases from your SIEM/ticketing tool (Splunk, Sentinel, TheHive, Jira — they all do JSON) and map the fields:

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
    "watch": true,
    "acknowledged": false,
    "iocs": ["194.26.135.12", "finance-secure-login.com"]
  }
]
```

| Field | Meaning |
|-------|---------|
| `severity` | critical, high, medium, low, info |
| `status` | new, investigating, containment, monitoring, closed |
| `shifts_open` | how many handoffs this case has survived (the big ones are survivors) |
| `watch` | pin it to the top |
| `acknowledged` | has the current shift actually looked at it, or just *looked at* it |
| `iocs` | IPs, domains, hashes — fuel for intel + memory |

## How the "steroids" actually work

<img src="https://media.giphy.com/media/l41lI4bYmcsPJX9Go/giphy.gif" width="260" align="right" alt="galaxy brain meme" />

- 🌐 **intel** is pluggable. Out of the box it uses a bundled local feed (so demos work on a plane). Point it at a real source — VirusTotal, AbuseIPDB, URLhaus — and it lights up for real.
- 🧠 **memory** is a tiny local JSON store at `~/.sochandoff/memory.json`. Every IOC it reports gets logged, so future shifts recognize repeats. No database. No server. No cloud bill.

## A note on the sample data

The bundled sample uses fixed timestamps, so as the days roll by, every sample case eventually reads as "stale" and gets flagged. That's not a bug, that's frozen demo data getting older, same as the rest of us. With live timestamps only genuinely stale cases flag.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest
pytest          # 22 tests, all green, we don't ship vibes
```

## License

MIT. Fork it, ship it, make your 6 AM handoff suck a little less.

<img src="https://media.giphy.com/media/111ebonMs90YLu/giphy.gif" width="200" alt="mic drop" />
