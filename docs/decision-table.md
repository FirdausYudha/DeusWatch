# Response decision table

DeusWatch routes every alert by an explicit **decision table** keyed on the alert's **entity
type** — the kind of security entity the alert concerns. One alert can touch several entities at
once (an external IP attacking one of your hosts over a request that carried a known-bad file
hash), and each entity type has its own response policy and its own owning engine.

The table is the **single source of truth**: the worker dispatches alerts by it and the
Response page / API display it, so the policy you see is exactly the policy that runs.

## The table

| Entity type   | Action                | Enforcement            | What happens |
|---------------|-----------------------|------------------------|--------------|
| `external_ip` | `block`               | **auto** · ban engine  | Ban the source IP at the firewall/router with a progressive duration; whitelisted IPs are never banned. |
| `host`        | `network_containment` | **auto** · containment engine | Isolate the compromised endpoint from the LAN (host self-isolation + a best-effort edge block) when a rule authorizes it. |
| `user`        | `alert`               | alert-only             | Surface the account for analyst review. DeusWatch does not auto-disable accounts. |
| `hash`        | `alert`               | alert-only             | A known-bad file hash raises the event to **High** via hash reputation; the file itself is not auto-quarantined. |

**Enforced** entities are executed automatically by their engine (subject to that engine's own
gating — auto-approve policy, severity thresholds, whitelist, dedup). **Alert-only** entities
are surfaced with full context but carry **no automated enforcement action** today; documenting
them here keeps the policy honest and gives those actions a defined home when enforcement is
added.

## How an alert is classified

An alert concerns an entity when the corresponding field is present:

- `external_ip` — the event has a `source.ip`.
- `host` — the event has an `agent.id` (one of your own endpoints).
- `user` — the event has a `user.name`.
- `hash` — the event has a `file.hash.sha256`.

The worker walks the entities in table order and dispatches each to the engine that owns its
action. This is behaviour-preserving: the engines already self-gate on exactly these conditions;
the table just makes the routing explicit and keeps it aligned with what the UI/API expose.

## Where it lives

- Policy + classifier: [`internal/respond/decision.go`](../internal/respond/decision.go).
- Dispatch: `makeAlertHook` in [`cmd/worker/main.go`](../cmd/worker/main.go).
- API: `GET /api/response/decision-table` (`view_dashboard`) →
  [`cmd/api/main.go`](../cmd/api/main.go).
- UI: the **Decision table** panel on the Response page.

Related engines: the perimeter IP-ban engine ([`internal/respond/engine.go`](../internal/respond/engine.go))
and network containment ([`internal/respond/containment.go`](../internal/respond/containment.go)).
