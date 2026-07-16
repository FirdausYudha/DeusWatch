# Ingest ModSecurity / OWASP CRS (WAF) into DeusWatch

DeusWatch parses **ModSecurity / OWASP CRS** WAF logs (e.g. from OPNsense or Apache) into
first-class events: the client IP, the WAF rule id + message, and the blocked URI / target host /
status. Repeated blocks from one IP raise an alert and feed the composite score, so a web scanner
can be **auto-banned at the firewall** (MikroTik / blocklist feed).

> DeusWatch is not itself a WAF — ModSecurity blocks the request inline; DeusWatch consumes its
> logs, correlates, scores, and bans the source across your network. Run them together.

## Get the logs in

Point any log path at DeusWatch — either an **agent** watching the file, or the
[ingest webhook](wazuh-webhook.md). ModSecurity/OPNsense writes the same block to a few places;
**pick ONE** so each event is counted once (see *Duplicates* below). The cleanest is the syslog
`httpd[…]: [security2:error]` stream (e.g. `/var/ossec/logs/opnsense_syslog.log` or Apache's
`error.log`).

**Agent source (Agents → the agent → add source):**

| Field | Value |
|---|---|
| dataset | `modsecurity` (any label works — the parser sniffs the ModSecurity signature) |
| type | `file` |
| path | the WAF/error log path, e.g. `/var/log/apache2/error.log` |

**Or webhook:** `POST /api/ingest/webhook?token=…&dataset=modsecurity` with the log lines as the body.

## What DeusWatch extracts

From a line like:

```
[client 165.22.76.50:17107] ModSecurity: Access denied with code 403 (phase 1). …
  [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"]
  [hostname "target.example"] [uri "/solr/admin/cores"] …
```

| Field | Mapped to |
|---|---|
| `[client IP:port]` | `source.ip` / `source.port` → scoring + **auto-ban** |
| `[id "…"]` | `rule.id` (the WAF/CRS rule) |
| `[msg "…"]` | `rule.name` |
| `code 403` | `http.status_code` |
| `[uri "…"]` | `http.uri` |
| `[hostname "…"]` | `http.host` (the requested vhost) |
| `[severity "…"]` | event severity (see below) |

The event is `event.action = waf_block`, `event.category = web`, shown on the dashboard with an
**HTTP request** block (method / URI / status / host).

### Severity mapping (deliberately conservative)

OWASP CRS labels most protocol-enforcement hits `CRITICAL` even for routine scanner noise, so
DeusWatch maps to avoid alert fatigue: `CRITICAL/ALERT/EMERGENCY → high`, `ERROR → medium`,
`WARNING → low`, else `info`. The **WAF Block Burst** rule (>10 blocks from one IP in 1 minute)
and the per-IP composite score are what surface the addresses worth banning.

## Duplicates

OPNsense/Apache emit the same block up to **3×** — an httpd RFC5424 copy, an httpd syslog copy,
and a `modsecurity[…]: Apache-Error:` copy — plus a noise `Producer:` line. Only the two httpd
copies carry `[client …]`; DeusWatch requires it, so the `modsecurity[…]` and `Producer` lines are
ignored automatically. To avoid the remaining httpd-vs-syslog duplicate, **ingest a single log
file** (stateless parsing can't dedup by `unique_id` across separate lines).

## Turn it into bans

1. Enable the **Web Attacks** rule pack (Rules → Rule packs) — it includes *WAF Block Burst*.
2. Configure a responder (MikroTik / blocklist feed) and set `RESPONSE_LIVE=1` — see
   [docs/mikrotik.md](mikrotik.md).
3. A scanner tripping the WAF repeatedly now scores up and is banned at the edge.
