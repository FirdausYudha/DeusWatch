# Connect DeusWatch to MikroTik (RouterOS)

DeusWatch can push ban decisions to MikroTik routers and keep them in sync. There are two
models - pick one:

| | **A. Push (built-in multi-sync)** | **B. Pull (blocklist feed)** |
|---|---|---|
| Who initiates | DeusWatch → router (RouterOS REST API) | Router → DeusWatch (a scheduler script) |
| REST API on the router | **required** | not needed |
| Inbound to the router | yes (from DeusWatch) | no (router only reaches out) |
| Self-signed cert issue | yes (see below) | none |
| Multi-router sync ~10s + self-heal | ✅ built-in | 🟡 up to your scheduler |
| Best when | you want central, plug-and-play control | you don't want the router's API exposed |

In **both** models the router's own firewall rule is what actually drops traffic - DeusWatch
only maintains the address-list.

---

## Model A - Push (REST API, multi-endpoint sync)

### 1. On each MikroTik (RouterOS v7)

```rsc
# Enable the REST API (served over HTTPS / the www-ssl service) with a certificate
/certificate add name=rest common-name=router-a
/certificate sign rest
/ip service set www-ssl certificate=rest disabled=no
/ip service set www-ssl address=10.10.0.254/32   ;# restrict to the DeusWatch IP (important)

# A dedicated user for DeusWatch (do not use admin)
/user add name=deuswatch password=STRONG-PASS group=write comment="DeusWatch API"

# The address-list DeusWatch fills + the filter rules that actually drop it
/ip firewall filter add chain=forward src-address-list=deuswatch_ban action=drop comment="DeusWatch ban"
/ip firewall filter add chain=input   src-address-list=deuswatch_ban action=drop
```

### 2. Multiple sites (buildings A / B / C)

DeusWatch must reach each router's REST API. On one routed LAN, just allow the DeusWatch IP.
**Across the internet, use a VPN - WireGuard is recommended** (built into RouterOS v7): each
router gets a stable private IP and the API is never exposed publicly.

```
DeusWatch site (WG hub, e.g. 10.10.0.254)
   ├── tunnel → MikroTik building A  (10.10.0.1)
   ├── tunnel → MikroTik building B  (10.10.0.2)
   └── tunnel → MikroTik building C  (10.10.0.3)
```

DeusWatch then targets `https://10.10.0.1`, `https://10.10.0.2`, `https://10.10.0.3`.

### 3. Add the router(s) in DeusWatch

**Integrations → + MikroTik** (one entry per router):

| Field | Value |
|---|---|
| `address` | `https://10.10.0.1` (the router's reachable/VPN IP) |
| `username` / `password` | the `deuswatch` user above |
| `address_list` | `deuswatch_ban` |
| `insecure_tls` | `true` if the router uses its **self-signed** cert (see below) |

Then set `RESPONSE_LIVE=1` in `deploy/.env` and restart the worker. The log shows
`responder from N Integrations MikroTik router(s)` and `blocklist sync active (reconcile
every 10s)`. Ban an IP → it appears in `/ip firewall address-list print where
list=deuswatch_ban` on **every** router within `RESPONSE_SYNC_INTERVAL` (default 10s), and a
rebooted router is re-populated automatically. Only entries commented `deuswatch` are managed;
manual entries are never touched.

### ⚠️ Self-signed certificate

RouterOS's REST API is HTTPS-only and the default certificate is **self-signed**, which fails
TLS verification. Two options:

- **Install a CA-trusted certificate** on the router (Let's Encrypt / your internal CA), or
- **Skip verification**: set `insecure_tls: true` on the integration (or `MIKROTIK_INSECURE=1`
  for the env path). This is safe **when the router is reached over a trusted tunnel**
  (WireGuard/IPsec) because the tunnel already encrypts and authenticates the connection.

---

## Model B - Pull (blocklist feed, no REST API)

The router fetches DeusWatch's active blocklist on a timer and applies it locally - no REST
API, no inbound to the router. See [blocklist-feed.md](blocklist-feed.md) for the token setup,
then on the router schedule a fetch into an address-list:

```rsc
/system script add name=deuswatch-bl source={
  /tool fetch url="http://<manager>:9080/api/blocklist?token=<TOKEN>" mode=http dst-path=deuswatch-bl.txt
  # parse the file and add each line to address-list "deuswatch_ban" (script), then it is dropped by:
}
/ip firewall filter add chain=forward src-address-list=deuswatch_ban action=drop comment="DeusWatch ban"
/system scheduler add name=deuswatch-bl interval=10s on-event=deuswatch-bl
```

> MikroTik has no native "import address-list from URL" (unlike Palo Alto EDL), so the pull
> model needs a small parse script you maintain. If you want zero router-side scripting and
> central control, prefer **Model A**.
