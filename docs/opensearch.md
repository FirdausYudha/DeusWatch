# Pull logs from OpenSearch / Elasticsearch (incl. the Wazuh indexer)

DeusWatch can **tail an existing OpenSearch / Elasticsearch index** and feed every document
into the normal pipeline (normalize → detect → playbooks → response). The headline use case:
the **Wazuh indexer *is* OpenSearch**, so DeusWatch reads `wazuh-alerts-*` directly and maps
each alert to its dashboard — no agent, no webhook wiring on the Wazuh side.

This is the **pull** counterpart to the [ingest webhook](wazuh-webhook.md) (push). Pick whichever
your environment allows; you can run both.

## Set it up (Integrations page)

**Integrations → OpenSearch / Elasticsearch (pull)**, then fill:

| Field | Value | Notes |
|---|---|---|
| `address` | `https://opensearch:9200` | The cluster URL. The Wazuh indexer listens on 9200. |
| `index` | `wazuh-alerts-*` | Index or pattern to tail. |
| `username` / `password` | a read user | Or use `api_key` instead. |
| `api_key` | ES/OpenSearch API key | Alternative to username/password. |
| `mode` | `auto` (default) | `auto` = map as a Wazuh alert if it looks like one, else a raw line; `wazuh` = always the Wazuh mapping; `raw` = always a raw log line (your decoders apply). |
| `timestamp_field` | `@timestamp` (default) | The field the tail sorts/pages on. |
| `query` | `rule.level:>=7` | Optional Lucene filter — pull only what you care about. |
| `poll_interval` | `30s` (default) | Go duration. |
| `insecure_tls` | `true` for a self-signed cluster cert | Safe over a trusted network/tunnel. |

Enable the integration. The worker logs, per cluster:

```
worker: es-pull "<name>" active (https://opensearch:9200/wazuh-alerts-* every 30s)
worker: es-pull "<name>": 42 hits, 42 published
```

Banned/enriched/scored events then appear on the dashboard exactly like agent- or webhook-shipped
ones (Wazuh alerts carry their own source IP, MITRE technique, severity, and `wazuh-agent` tag).

## How the tail works

DeusWatch sorts by `timestamp_field` ascending and pages forward with `search_after`, persisting
the last position as a **cursor** (`ingest_cursor` table, keyed per integration). A worker restart
**resumes where it left off** — no replay, no gap. With no cursor yet, it starts from a short
look-back window (5 minutes) so enabling the connector doesn't replay the whole index.

> **Limitation (honest note):** progress is timestamp-based. A document indexed *late* with an
> older timestamp, or many documents sharing the exact same timestamp split across a batch
> boundary, can be missed. This is the normal trade-off of timestamp tailing and is fine for
> append-mostly alert streams. For lossless delivery from Wazuh, prefer the push
> [webhook](wazuh-webhook.md) (the Wazuh integrator POSTs each alert as it fires).

## Credentials

The username/password and API key are **encrypted at rest** (like every Integrations secret) and
never read back through the API. Use a **read-only** account scoped to the index you tail.
