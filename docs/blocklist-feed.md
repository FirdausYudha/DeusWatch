# Blocklist feed - sync bans to external firewalls

DeusWatch can publish its **currently-banned IPs** as a dynamic block list that any firewall
fetches on a schedule. This is the vendor-agnostic way to enforce your bans everywhere: instead
of DeusWatch pushing to each device's API, each firewall **pulls** one URL - exactly the "external
dynamic list" feature these products already have.

## Enable it

**From the UI (recommended):** **Response** page → **Blocklist feed** panel → **Enable feed
(generate token)**. It shows the ready-to-use URL with a **Copy** and **Regenerate token** button
(admin / `manage_settings` only). Regenerating rotates the token and invalidates the old URL.

**From env (optional seed):** set `BLOCKLIST_FEED_TOKEN` in `deploy/.env` and it is loaded into
the DB on first start (so an existing deployment keeps working); after that, manage it in the UI.

```bash
# optional, in deploy/.env
BLOCKLIST_FEED_TOKEN=$(openssl rand -hex 24)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d api
```

The feed is then at:

```
http://<manager>:9080/api/blocklist?token=<TOKEN>            # one IP per line (default)
http://<manager>:9080/api/blocklist?token=<TOKEN>&format=json
```

- Contains the IPs that are **currently blocked** (approved/executed and not expired). Unbanned
  or expired IPs drop off automatically, so a firewall that re-fetches also **un-blocks**.
- Unauthenticated except for the token (firewalls can't do session login), so keep the token
  secret and prefer serving it over the LAN / VPN or behind TLS. Empty token = feed disabled (404).

> Put the manager behind HTTPS (a reverse proxy) if a firewall fetches it across an untrusted
> network - the token travels in the URL.

## Wire each firewall (all pull the same URL)

**Palo Alto - External Dynamic List (EDL)**
Objects → External Dynamic Lists → Add → Type **IP List**, Source =
`http://<manager>:9080/api/blocklist?token=<TOKEN>`, set a check interval (e.g. every 5 min).
Then reference the EDL in a Security policy rule that **denies** it. (Palo Alto ignores `#`
comment lines.)

**OPNsense - URL Table alias**
Firewall → Aliases → Add → Type **URL Table (IPs)**, Content = the feed URL, refresh frequency
in days/hours. Use the alias in a **block** rule on WAN.

**pfSense - pfBlockerNG**
pfBlockerNG → IP → add a custom list with the feed URL, action **Deny**, set the update
frequency. pfBlockerNG builds the pf table and the block rule.

**MikroTik RouterOS** (if you prefer the feed over the built-in push responder)
A scheduled script fetches the list into an address-list, then a firewall rule drops it:

```
/tool fetch url="http://<manager>:9080/api/blocklist?token=<TOKEN>" mode=http dst-path=deuswatch.txt
# then import each line into an address-list (script), and:
/ip firewall filter add chain=forward src-address-list=deuswatch action=drop
```

> MikroTik is also supported as a **push** responder with **multi-endpoint sync** (Integrations →
> MikroTik) - DeusWatch writes bans straight to a RouterOS address-list via the REST API and
> keeps every router reconciled within ~10s. Full setup (REST API, WireGuard for multi-site,
> self-signed cert / `insecure_tls`, and this pull alternative) is in **[docs/mikrotik.md](mikrotik.md)**.
> Use whichever you prefer; the feed suits fleets and non-API devices.

**CrowdSec** is integrated separately as a bouncer (Integrations → CrowdSec LAPI).

## Notes

- The feed is **read-only** and derived from the Response engine's live state - there is nothing
  to keep in sync by hand.
- Bare IPs are emitted; firewalls treat them as `/32`. (Whitelisted IPs are never banned, so they
  never appear here.)
