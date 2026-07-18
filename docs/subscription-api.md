# Subscription API (the sellable rich-log product)

DeusWatch can expose its **enriched telemetry as a subscription product**: external subscribers
pull enriched events and curated threat indicators over a simple, token-authed HTTP API, each
with their own revocable API key and usage accounting. This is the packaging layer that turns
DeusWatch's rich, scored, MITRE-labelled logs into something you can hand to a customer, a
partner SOC, or another internal team.

- **Per-subscriber API keys.** Each key is shown **once** at creation; only its SHA-256 is
  stored. Revoke or disable any key independently.
- **Scopes.** A key grants `events`, `indicators`, or both.
- **Usage tracking.** Every call bumps `request_count` and `last_used_at` for billing and
  revocation decisions.
- **Forward-only cursor pagination** with a **settle lag**, so subscribers get a complete,
  gap-free, already-enriched stream.

Management is **admin-only** (`manage_integrations`) under **Settings → Log subscriptions (API)**.

## Manage keys (admin)

Settings → **Log subscriptions (API)** → set a name, minimum severity, and scopes → **Create
key**. Copy the key immediately — it is not retrievable again. You can Disable (temporarily) or
Revoke (permanently) any key later.

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/subscriptions` | list subscribers (no secrets) | `manage_integrations` |
| `POST /api/subscriptions` | create → returns the one-time key | `manage_integrations` |
| `POST /api/subscriptions/{id}/toggle` | enable/disable | `manage_integrations` |
| `DELETE /api/subscriptions/{id}` | revoke permanently | `manage_integrations` |

## Consume the feed (subscriber)

Authenticate with the API key via `Authorization: Bearer <key>`, the `X-API-Key` header, or a
`?key=` query parameter.

### Events — `GET /api/subscribe/events`

Forward-only, cursor-paginated enriched events (requires the `events` scope).

| Param | Meaning |
|---|---|
| `cursor` | opaque resume token from the previous response's `next_cursor` (omit on first call) |
| `from` | RFC3339 start time, used only when `cursor` is empty (skip old history) |
| `limit` | page size (default 200, max 1000) |
| `min_severity` | raise the floor above the key's configured minimum (cannot lower it) |

```bash
# first page
curl -H "Authorization: Bearer dws_…" \
  "https://deuswatch.example/api/subscribe/events?from=2026-07-18T00:00:00Z&limit=500"

# then keep pulling with the returned cursor
curl -H "Authorization: Bearer dws_…" \
  "https://deuswatch.example/api/subscribe/events?cursor=<next_cursor>"
```

Response:

```json
{
  "events": [ { "time": "…", "event_severity": 4, "source_ip": "203.0.113.9",
                "dw_label": "bruteforce", "threat_score": 82, "…": "…" } ],
  "next_cursor": "MTc1…",
  "has_more": true
}
```

Loop: pull with `cursor`, process `events`, save `next_cursor`; when `has_more` is false, wait
and poll again with the same cursor. The cursor encodes the last `(time, id)` delivered, so
resumption is exact — no gaps, no duplicates.

### Indicators — `GET /api/subscribe/indicators`

Curated scored source IPs, highest score first (requires the `indicators` scope).

| Param | Meaning |
|---|---|
| `min_score` | only return indicators at/above this composite score |
| `limit` | max rows (default 200, max 1000) |

```bash
curl -H "Authorization: Bearer dws_…" \
  "https://deuswatch.example/api/subscribe/indicators?min_score=50"
```

## The settle lag

Enrichment (CTI lookups, composite scoring) completes a few seconds after an event is first
written. So the events feed only serves records **older than a settle window** — default **30s**,
tunable with `SUBSCRIPTION_SETTLE_LAG` (e.g. `10s`, `1m`) — guaranteeing subscribers always
receive the final, enriched form of each event rather than a half-enriched one.

## Notes & limitations

- The feed advances by event time. Enrichment that lands *after* the settle window (rare) is not
  re-sent — raise `SUBSCRIPTION_SETTLE_LAG` if your enrichment is slow.
- Keys are bearer credentials: serve the API over TLS and treat a key like a password. Rotate by
  creating a new key and revoking the old one.
- This is a **pull** product. For **push** delivery to a single endpoint, use the Export (webhook
  JSON) integration instead.
