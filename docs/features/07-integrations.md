# 7. Integrations

Connectors to external systems. **All connectors are compiled Go drivers** (not Python apps) -
only their *config* lives in the DB, encrypted at rest.

## How it works

- The **Catalog** lists connector types by category: **CTI** (AbuseIPDB, AlienVault OTX),
  **Firewall** (nftables agent-side, MikroTik), **Bouncer** (CrowdSec LAPI), **LLM**
  (Claude/Ollama/OpenAI-compatible), **FIM reputation** (VirusTotal, CIRCL), **Export**
  (webhook JSON).
- You save config (API key, URL, creds) per connector. **Secrets are AES-GCM encrypted** with
  `SECRETS_KEY` and are **write-only** (masked in the UI).
- Consumers resolve them at startup: the worker's **enrichment** uses CTI/FIM, the **response
  engine** uses firewall/bouncer, and **LLM** powers **triage** and/or **reports** per the
  connector's **Use for** setting. The Integrations registry takes precedence over the
  equivalent env vars.
- CTI provider **live-reloads** (~1 min) - adding an AbuseIPDB key (or changing its **cache
  window**) in the UI takes effect without restarting the worker. Response/LLM drivers are
  picked up at worker start.
- **MikroTik multi-endpoint sync (CrowdSec-bouncer style):** add **several** MikroTik
  connectors and every ban/unban fans out to **all** of them. A periodic reconcile
  (`RESPONSE_SYNC_INTERVAL`, default **10s**) makes each router's `address_list` exactly
  equal to DeusWatch's active blocks - so a block added/removed in DeusWatch reaches every
  router within seconds, and a router that **rebooted** (losing its list) is automatically
  re-populated. Only entries DeusWatch created (comment `deuswatch`) are ever removed;
  manually-added address-list entries are left untouched. Requires `RESPONSE_LIVE=1`. Set
  `insecure_tls: true` on the connector when the router presents a self-signed certificate
  (safe over a WireGuard/IPsec tunnel). **Full setup (RouterOS REST API, WireGuard for
  buildings A/B/C, the pull alternative): [docs/mikrotik.md](../mikrotik.md).**
- Each CTI connector (AbuseIPDB / OTX) carries its own **cache window (hours)** - the dedup TTL
  that serves a recently-looked-up IP from cache instead of re-querying the API (protects your
  quota; default 24, AbuseIPDB's value wins if both are set).

## How to use

- **Integrations** menu → pick a type from the catalog → fill fields (e.g. AbuseIPDB
  `api_key`) → **Enable**.
- For **AbuseIPDB / OTX** set the API key and, optionally, the **Cache window (hours)**. Real
  threat-intel is active whenever an enabled CTI connector has a key (otherwise the Threat
  Intel column shows "-").
- **LLM**: pick **Provider** (ollama / openai-compatible / anthropic) and **Use for** (triage /
  report / both). All providers (OpenAI, Gemini, Groq, Claude) + the triage-vs-report selector
  are in [docs/llm-providers.md](../llm-providers.md); Ollama connect + troubleshooting (DNS,
  nginx 504, slow model) is in [docs/llm-ollama.md](../llm-ollama.md).

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/integrations/types` | connector catalog | `manage_integrations` |
| `GET/POST /api/integrations` | list / add | `manage_integrations` |
| `PUT/DELETE /api/integrations/{id}` | edit / remove | `manage_integrations` |

Frontend: [`web/src/integrations/`](../../web/src/integrations/). Backend:
[`internal/integrations/`](../../internal/integrations/), encryption
[`internal/secret/`](../../internal/secret/), CTI clients
[`internal/enrich/clients.go`](../../internal/enrich/clients.go).

## Ports / tech

- Browser → Web `9173` → API `9080`. Outbound calls (AbuseIPDB/OTX/VirusTotal/LLM) go over
  HTTPS from the worker; MikroTik/CrowdSec over their own APIs. Language: **Go** drivers.

## Variables

- **`SECRETS_KEY`** in `deploy/.env` (base64 of 32 bytes) - encrypts integration secrets.
  Without it a fixed DEV key is used (not safe for production); changing it later makes stored
  secrets undecryptable (re-enter them).
- Each connector's credentials are entered **in the UI** (preferred) or via env fallbacks
  (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GEOIP_ENABLED`, `ANTHROPIC_API_KEY`, `WEBHOOK_URL`, …).
- **Extending**: a new connector = one Go file implementing the driver interface
  (`Provider` / `Responder` / `Notifier`) + rebuild. For no-code long-tail, use the **Export
  webhook** to hand off to n8n/Zapier.
