# Network Containment (host isolation)

Automatically isolate a **compromised agent host** from the LAN — everything except the
manager — when a rule detects a serious threat (ransomware behaviour, a user opening malware,
a phishing click). This stops lateral spread to file servers, storage and other users while
keeping the host reachable from DeusWatch so an analyst can investigate and release it.

This is distinct from the perimeter **IP-ban** engine (`internal/respond/engine.go`), which
blocks an *external attacker's* source IP. Containment targets *our own* endpoints.

## How it works (end to end)

1. **Rule authorizes it.** A detection rule carries a `mitigation_action: network_containment`
   block (parsed by `internal/detect/sigma`). When it fires, the alert is stamped with the
   directive (`deuswatch.containment` — see `internal/ingest`).
2. **Evaluator decides.** In the worker, `respond.ContainmentEngine.Evaluate` runs on every
   alert (real-time, thread-safe). It:
   - checks the rule authorized containment **and** the alert severity ≥ `criticality_threshold`;
   - extracts the `agent_id` (mTLS CN) and `ip_address` (host IP) from the alert;
   - prevents **double-containment** — an agent can have at most one open action (enforced by
     a partial unique index, so concurrent alerts collapse to one);
   - never isolates the **manager's own host** (`DEUSWATCH_MANAGER_IPS`).
3. **Enforcement — both points:**
   - **Host self-isolation (primary):** the record drives a per-agent directive the agent
     polls (`GET /v1/containment`, by mTLS CN). The agent firewalls itself off
     (`nftables` on Linux, `netsh advfirewall` on Windows), permitting only loopback,
     established flows, and the allow-list (manager/DNS). It **always** keeps its own gateway
     reachable, so the manager link — and the ability to lift isolation — can never be cut.
   - **Edge block (best-effort):** the host IP is also blocked at the network edge via the
     existing responder (nftables/MikroTik/CrowdSec) when the IP is known.
4. **Release.** Manual (analyst) or automatic after `timeout` seconds (worker sweep). The agent
   sees no active directive on its next poll and clears its firewall.

## Rule schema — `mitigation_action`

```yaml
mitigation_action:
  action_type: network_containment
  timeout: 1800                 # auto-release after N seconds (0 = until manual release)
  criticality_threshold: high   # min alert severity for AUTOMATIC containment
```

Example: [`rules/sigma/ransomware_shadowcopy_containment.yml`](../../rules/sigma/ransomware_shadowcopy_containment.yml).

## Configuration

**Manager (worker):**

| Env | Meaning |
|---|---|
| `CONTAINMENT_AUTO=1` | Enable automatic containment. When off, qualifying alerts create a **recommended** action awaiting analyst approval. |
| `DEUSWATCH_MANAGER_IPS` | Comma-separated IP/CIDR of the manager's own hosts — never contained. |
| `DEUSWATCH_CONTAINMENT_ALLOW_IPS` | Comma-separated IPs an isolated host must keep reachable (manager, DNS). The agent also always allows its own gateway. |

**Agent:**

| Env | Meaning |
|---|---|
| `AGENT_CONTAINMENT=1` | Opt the host into isolation (polls `GET /v1/containment`). Off by default. Linux needs `nft` + root; Windows needs `netsh` + Administrator. |

## Safety rails

- Auto-contain is **off by default** (`CONTAINMENT_AUTO`), and even when on it only fires
  at/above the rule's `criticality_threshold` (defaults to `high` if unset).
- The agent's link to the manager is never severed (gateway IP is always allowed), so an
  isolated host keeps reporting and can always be released.
- The manager's own host is never contained.
- Host self-isolation is the primary control and works with no network gear; the edge block
  is best-effort and never blocks containment if it fails.
