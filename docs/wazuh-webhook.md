# Ingest raw logs from a Wazuh manager (webhook)

DeusWatch can receive **raw log lines** pushed over HTTP - e.g. from a Wazuh manager's
integrator - and run them through the normal pipeline (normalize -> custom decoders ->
detection -> playbooks -> response). Each source is tagged so you can tell it apart on the
dashboard.

## 1. Enable the webhook (manager side)

Set a token in `deploy/.env` (empty = the endpoint is disabled and returns 404):

```dotenv
# Generate: openssl rand -hex 24
INGEST_WEBHOOK_TOKEN=paste-a-long-random-token
```

Apply: `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d api`.

The endpoint:

```
POST http://<manager>:9080/api/ingest/webhook?token=<TOKEN>&agent=<name>&dataset=wazuh
```

| Query param | Meaning | Default |
|---|---|---|
| `token` | Auth (or send `Authorization: Bearer <token>`) | required |
| `agent` | Source name -> shown on the dashboard as `wazuh-agent/<name>` | `wazuh-agent` |
| `dataset` | The dataset your decoders target | `wazuh` |
| `host` | Optional `host.name` for the event | - |

**Body — three accepted shapes** (up to 2000 items / 4 MiB; response `{"accepted": N}`):

1. **Wazuh alert JSON** - a single alert object, or a JSON array of them. Wazuh has already
   decoded the log, so DeusWatch maps its fields straight to the dashboard:
   `data.srcip` → source IP (+ `GeoLocation` country), `rule.description` → rule name,
   `rule.level` → severity (0-15 → info…critical), `rule.mitre` → MITRE technique/tactic,
   `agent.name` → host + the `wazuh-agent/<name>` tag, `data.dstuser` → user, `full_log` →
   the raw line. The MITRE **tactic becomes the label** (e.g. `credential_access`) so the
   matching **playbook** applies and the alert can drive response. An `_source` envelope
   (pasted from the indexer) is unwrapped automatically.
2. A **JSON array of raw log-line strings** - each is normalized with the query `agent`/`dataset`.
3. **Newline-separated raw lines** (`text/plain`) - same.

So you can send Wazuh's rich alerts (recommended - the dashboard shows real fields) OR just
the raw `full_log` line and parse it yourself with a **custom decoder** on the `wazuh` dataset.

Quick test:

```bash
curl -X POST "http://<manager>:9080/api/ingest/webhook?token=<TOKEN>&agent=web-01" \
  --data-binary 'Jan 1 00:00:00 web-01 sshd[1]: Failed password for admin from 1.2.3.4 port 22 ssh2'
```

The line appears in **Events** with agent `wazuh-agent/web-01`. Turn off the alerts-only
filter to see raw ingested lines.

## 2. Point Wazuh at it (Wazuh side)

Wazuh's `integrator` daemon can POST alerts to a custom hook. In the Wazuh manager's
`/var/ossec/etc/ossec.conf`, add an integration whose script forwards the raw log
(`full_log`) to the URL above. A minimal custom integration script (`custom-deuswatch`)
reads the alert JSON on stdin and POSTs `.full_log` to the webhook:

```bash
#!/bin/sh
# /var/ossec/integrations/custom-deuswatch  (chmod 750, owner root:wazuh)
ALERT_FILE="$1"
HOOK="http://<manager>:9080/api/ingest/webhook?token=<TOKEN>&agent=wazuh-manager&dataset=wazuh"
LINE=$(sed -n 's/.*"full_log"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$ALERT_FILE" | head -1)
[ -n "$LINE" ] && curl -s -X POST "$HOOK" --data-binary "$LINE" >/dev/null
```

```xml
<!-- ossec.conf -->
<integration>
  <name>custom-deuswatch</name>
  <hook_url>http://<manager>:9080/api/ingest/webhook</hook_url>
  <level>3</level>            <!-- forward alerts at/above this Wazuh level -->
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh: `systemctl restart wazuh-manager`. (Parsing is done on the DeusWatch side
via **custom decoders** targeting the `wazuh` dataset - write them from the Decoders menu,
testing against the real lines the webhook receives.)

> **Note:** the webhook is plain HTTP on the API port. For traffic that leaves the host,
> put it behind the same TLS reverse proxy as the UI (see [production.md](production.md))
> and POST to the HTTPS URL instead.
