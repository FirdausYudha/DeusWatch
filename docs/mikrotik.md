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

### 2. Multiple sites (buildings A / B / C) - WireGuard

DeusWatch must reach each router's REST API. On one routed LAN, just allow the DeusWatch IP.
**Across the internet, use a VPN - WireGuard is recommended** (built into RouterOS v7): the
DeusWatch server is the hub, each router a spoke with a stable private IP; the API is never
exposed publicly.

```
DeusWatch hub 10.10.10.1/24
   ├── tunnel → MikroTik A  10.10.10.8/24
   ├── tunnel → MikroTik B  10.10.10.9/24
   └── tunnel → MikroTik C  10.10.10.10/24
```

**On the DeusWatch server (Linux hub):**

```bash
sudo apt install -y wireguard
wg genkey | sudo tee /etc/wireguard/hub.key | wg pubkey | sudo tee /etc/wireguard/hub.pub
sudo tee /etc/wireguard/wg0.conf >/dev/null <<'EOF'
[Interface]
Address = 10.10.10.1/24
ListenPort = 51820
PrivateKey = <HUB_PRIVATE_KEY>          # from /etc/wireguard/hub.key
[Peer]                                  # MikroTik A (repeat a [Peer] block per router)
PublicKey = <MIKROTIK_A_PUBLIC_KEY>
AllowedIPs = 10.10.10.8/32
EOF
sudo ufw allow 51820/udp
sudo systemctl enable --now wg-quick@wg0
```

**On each MikroTik (RouterOS v7):**

```rsc
/interface/wireguard/add name=wg-deuswatch listen-port=51820
/interface/wireguard/print              ;# read this router's public-key -> put in the hub's [Peer]
/ip/address/add address=10.10.10.8/24 interface=wg-deuswatch
/interface/wireguard/peers/add interface=wg-deuswatch \
  public-key="<HUB_PUBLIC_KEY>" \
  endpoint-address=<DEUSWATCH_PUBLIC_IP> endpoint-port=51820 \
  allowed-address=10.10.10.0/24 persistent-keepalive=25s
/ip/firewall/filter/add chain=input in-interface=wg-deuswatch src-address=10.10.10.1 action=accept place-before=0 comment="DeusWatch WG"
/ip/service/set www-ssl address=10.10.10.1/32   ;# only the hub may reach the REST API
```

Key exchange: the router's public key (`/interface/wireguard/print`) goes into the hub's
`[Peer] PublicKey`; the hub's public key (`/etc/wireguard/hub.pub`) goes into the router's
`peers add public-key=`. Restart the hub after adding peers: `sudo systemctl restart
wg-quick@wg0`. Verify with `sudo wg show` (a handshake appears) and `ping 10.10.10.8`.

DeusWatch then targets `https://10.10.10.8`, `https://10.10.10.9`, `https://10.10.10.10`
(with `insecure_tls: true`, since the tunnel already secures the connection).

> **Docker note:** WireGuard runs on the **host**, but the worker runs in a **container**.
> Add a masquerade so container traffic uses the tunnel's source IP, or it is dropped by the
> peer's `allowed-address`: `sudo iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE`.

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

### 4. Verify it works (startup self-check)

On start, the worker probes every configured MikroTik and prints the result - **read these
lines first** (`docker compose -f deploy/docker-compose.yml logs worker`):

```
worker: responder from 1 Integrations MikroTik router(s): MikroTik Test
worker: MikroTik "MikroTik Test" REST check OK (list=deuswatch_ban reachable)   ← REST/TLS/auth all good
respond: LIVE responder active: mikrotik                                        ← RESPONSE_LIVE=1 is set
worker: blocklist sync active (reconcile every 10s to mikrotik)                 ← the sync loop is running
```

If the check **fails**, the log names the exact cause, e.g.:

```
worker: MikroTik "MikroTik Test" REST check FAILED: cannot reach https://10.10.10.8 (...) -
  check the tunnel/route and that /ip service www-ssl 'address=' allows the DeusWatch hub IP
worker: MikroTik "MikroTik Test" REST check FAILED: HTTP 401 ... - wrong username/password
```

Then ban an IP in **Response** and confirm it lands on the router within ~10s:

```bash
curl -k -i -u deuswatch:PASS https://10.10.10.8/rest/ip/firewall/address-list
# expect HTTP/1.1 200 and an entry {"address":"…","list":"deuswatch_ban","comment":"deuswatch"}
```

---

## Troubleshooting

Symptoms are ordered by how often they bite. The worker's startup REST check (above) will
usually point straight at the row here.

| Symptom | Cause | Fix |
|---|---|---|
| **Bans never appear on the router, no errors** | `RESPONSE_LIVE` is not set → the responder is wrapped in **dry-run**, so the sync loop never runs. The log says `responder … wrapped in dry-run` and `NOTE - MikroTik is configured but RESPONSE_LIVE!=1`. | Set `RESPONSE_LIVE=1` in `deploy/.env`, then **`docker compose -f deploy/docker-compose.yml up -d --force-recreate worker`** (a plain restart does not re-read `.env`). |
| `curl: (35) Recv failure: Connection reset by peer` / REST check "cannot reach" | `/ip service www-ssl` has `address=` set to a value that **excludes the DeusWatch hub** (a common mistake is setting it to the router's own tunnel IP, e.g. `10.10.10.8/32`). RouterOS resets connections from disallowed sources during the TLS handshake. | On the router: `/ip service set www-ssl address=10.10.10.0/24` (allow the whole tunnel subnet, which includes the hub `10.10.10.1`). Re-run the `curl`. |
| REST check `HTTP 401` | Wrong username/password, or the user lacks API rights. | `/user print` on the router; the DeusWatch user needs `group=write`. Re-enter the password in **Integrations → MikroTik**. |
| REST reachable (`200 []`) but **bans still don't drop traffic** | The `address_list` in the integration does **not** match the address-list in your `/ip firewall filter` drop rule (e.g. form says `deuswatch`, rule uses `deuswatch_ban`). DeusWatch writes to a list nothing is dropping. | Make both identical. Set **Integrations → MikroTik → `address_list` = `deuswatch_ban`** and confirm `/ip firewall filter print` has a rule with `src-address-list=deuswatch_ban action=drop`. |
| REST works from the **host** but the worker's check fails (container only) | WireGuard runs on the host; the worker runs in a container. Its traffic leaves with a container source IP that the peer's `allowed-address` drops. | Add the masquerade so container traffic uses the tunnel IP: `sudo iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE` (persist it via `iptables-persistent`). |
| REST check TLS error mentioning certificate | The router presents its **self-signed** cert and `insecure_tls` is off. | Set **Integrations → MikroTik → `insecure_tls` = `true`** (safe over a WireGuard/IPsec tunnel), or install a CA-trusted cert on the router. |
| `docker compose … logs` → *no such file or directory* | Run from the wrong directory - the compose file is at `deploy/docker-compose.yml` **relative to the repo root**. | `cd` into the repo root first (the folder that contains `deploy/`), then run the compose command. |
| A rebooted router loses its bans | Expected only briefly - the reconcile loop re-populates the address-list within `RESPONSE_SYNC_INTERVAL` (default 10s). | Nothing; if it persists, the router isn't reachable - check the startup REST line. |

> DeusWatch only manages entries it created (comment `deuswatch`). Your manually-added
> address-list entries are never touched or removed by the sync.

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
