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
  engine** uses firewall/bouncer, **reports** use LLM. The Integrations registry takes
  precedence over the equivalent env vars.
- CTI provider **live-reloads** (~1 min) - adding an AbuseIPDB key in the UI activates real
  lookups without restarting the worker. Response/LLM drivers are picked up at worker start.

## How to use

- **Integrations** menu → pick a type from the catalog → fill fields (e.g. AbuseIPDB
  `api_key`) → **Enable**.
- Threat Intel status is shown in **Settings → Threat-intel (CTI) caching** (real vs mock).
- **LLM (Ollama / OpenAI-compatible)**: step-by-step connect + troubleshooting (DNS, nginx 504,
  slow model) is in [docs/llm-ollama.md](../llm-ollama.md).

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
