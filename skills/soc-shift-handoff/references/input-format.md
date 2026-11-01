# Input format

sochandoff reads a JSON list of cases, or a CSV with the same columns.

## Fields

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | yes | string | Must be unique |
| `title` | yes | string | |
| `severity` | yes | string | critical, high, medium, low, info |
| `status` | yes | string | new, investigating, containment, monitoring, closed |
| `opened_at` | yes | ISO 8601 | `2026-10-31T06:00:00Z` |
| `last_update` | yes | ISO 8601 | Drives staleness |
| `assignee` | no | string | Default `unassigned` |
| `shifts_open` | no | int | Handoffs survived |
| `watch` | no | bool | Pin to top |
| `acknowledged` | no | bool | Current shift has seen it |
| `notes` | no | string | |
| `tags` | no | list | CSV: split with `;` |
| `iocs` | no | list | IPs, domains, hashes. CSV: split with `;` |

Unknown fields are rejected, so the user learns about typos.

## Mapping other tools

Convert the export with a short script (jq or Python) into the fields above.
Common mappings:

| Tool | id | severity | status | last_update |
|------|----|----------|--------|-------------|
| Splunk ES notable | `event_id` | `urgency` | `status_label` | `_time` |
| Microsoft Sentinel incident | `properties.incidentNumber` | `properties.severity` | `properties.status` | `properties.lastModifiedTimeUtc` |
| Jira | `key` | `priority.name` | `status.name` | `fields.updated` |
| ServiceNow SIR | `number` | `priority` | `state` | `sys_updated_on` |

Map their values onto sochandoff's words. Example Sentinel map:
`High -> high`, `Medium -> medium`, `Low -> low`, `Informational -> info`;
`New -> new`, `Active -> investigating`, `Closed -> closed`.

Write the converted file to a temp path, then run `sochandoff that.json -f json`.
Never hardcode a token in the conversion script; read it from the environment.
