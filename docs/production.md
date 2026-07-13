# Production hardening guide

How to run DeusWatch on a real network instead of a lab: secrets, TLS, login
protection, network exposure, backups, and updates. Everything here is optional for
local experiments and strongly recommended the moment other people depend on the box.

## 1. Checklist (do these before exposing anything)

| # | Action | How |
|---|---|---|
| 1 | Change the admin password | `ADMIN_PASSWORD` in `deploy/.env` **before first start**, or Settings → Change password after |
| 2 | Change the DB password | `POSTGRES_PASSWORD` in `deploy/.env` (takes effect on a fresh db volume) |
| 3 | Set a real secrets key | `SECRETS_KEY` = `openssl rand -base64 32` (integration secrets are AES-256-GCM encrypted with it) |
| 4 | Enable 2FA for admins | Settings → Two-factor authentication (TOTP) |
| 5 | Keep self-registration off | `REGISTRATION_ENABLED=0` (the default) |
| 6 | Put the UI/API behind TLS | reverse proxy - section 3 |
| 7 | Restrict exposed ports | section 4 |
| 8 | Schedule backups | section 5 |
| 9 | Keep the stack updated | `./scripts/update.sh` + the in-app update check |

## 2. Login protection (built in, on by default)

The API locks out brute-force login attempts: after **5 failed logins** (per source IP
*and* per username) within the lockout window, further attempts get HTTP 429 for
**15 minutes**. Lockouts are recorded in the audit log as `login_locked`. New passwords
(register / create user / change password) must be at least 8 characters, must not be a
top-list common password, the username, or one repeated character.

Tune via `deploy/.env` (defaults shown):

```dotenv
LOGIN_MAX_FAILURES=5      # 0 disables the limiter
LOGIN_LOCKOUT=15m         # lockout duration AND failure-counting window (Go duration)
PASSWORD_MIN_LEN=8        # floor for NEW passwords (existing logins unaffected; min 8)
```

**Client IPs behind the bundled proxy.** The web container (nginx) proxies `/api` and
forwards the real client address in `X-Forwarded-For`. The API only trusts that header
when the direct peer is inside `TRUSTED_PROXIES` (default `172.16.0.0/12`, the Docker
network range), so an external client can never spoof its own IP to dodge the rate
limiter or pollute the audit log. If you terminate TLS with an extra proxy *on another
machine*, add that machine's IP to `TRUSTED_PROXIES` (comma-separated CIDRs or IPs).

## 3. TLS for the web UI and API

Agent↔gateway traffic is **already mTLS** end-to-end. What ships in plain HTTP is the
browser side: the web UI (`:9173`) and the API it proxies. Put a TLS reverse proxy in
front and stop exposing the plain ports to the network.

### Option A - Caddy (automatic Let's Encrypt, recommended)

On the manager host, with a DNS record pointing at it:

```bash
sudo apt install caddy        # Debian/Ubuntu; see caddyserver.com for others
```

`/etc/caddy/Caddyfile`:

```caddy
deuswatch.example.com {
    reverse_proxy localhost:9173
}
```

```bash
sudo systemctl reload caddy
```

Caddy obtains and renews the certificate automatically and sets `X-Forwarded-For`
(the chain stays intact through the web container - no extra config needed). Then
firewall `9173` from external access (section 4).

### Option B - nginx + certbot

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

`/etc/nginx/sites-available/deuswatch`:

```nginx
server {
    server_name deuswatch.example.com;
    location / {
        proxy_pass http://127.0.0.1:9173;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # AI report generation can take >60s on slow local LLMs.
        proxy_read_timeout 180s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/deuswatch /etc/nginx/sites-enabled/
sudo certbot --nginx -d deuswatch.example.com
```

> **No public domain?** For LAN-only deployments use Caddy's `tls internal` (self-signed
> with a local CA) or keep plain HTTP inside a VPN (WireGuard/Tailscale) - the important
> part is that credentials never cross an untrusted network unencrypted.

## 4. Network exposure

Only two ports need to be reachable by anything remote:

| Port | Who needs it | Recommendation |
|---|---|---|
| `443` (proxy) | Browsers (UI/API via TLS) | expose |
| `9080` (api) | Agents: enroll + one-line installer | LAN/VPN only |
| `9443` (gateway) | Agents: mTLS log shipping + heartbeat | LAN/VPN only |
| `9173` (web, plain) | Nobody once TLS is up | firewall it (proxy reaches it via localhost) |
| `5432` (db), `4222`/`8222` (NATS) | Nobody external | **bound to 127.0.0.1 by default** |

The db and NATS host mappings bind to loopback out of the box. If a streaming-replication
standby must reach Postgres from another machine (see [storage.md](storage.md)), set
`DEUSWATCH_DB_BIND=0.0.0.0` in `deploy/.env` and allow only the standby's IP in the
host firewall.

Example (Linux/ufw):

```bash
sudo ufw allow 443/tcp
sudo ufw allow from 192.168.0.0/16 to any port 9080,9443 proto tcp   # agents' LAN
sudo ufw deny 9173/tcp
```

Container memory caps are set in compose (db/worker 1g, api/gateway/nats 512m, web
128m; override via `DEUSWATCH_DB_MEM` / `DEUSWATCH_WORKER_MEM`) so one runaway
service cannot OOM the host.

## 5. Backup & restore

**Back up** (stack keeps running; dumps to `./backups`, keeps the newest 14):

```bash
./scripts/backup.sh                       # .\scripts\backup.ps1 on Windows
BACKUP_KEEP=30 ./scripts/backup.sh /mnt/nas/deuswatch
```

Cron (daily 03:30):

```cron
30 3 * * *  cd /path/to/DeusWatch && ./scripts/backup.sh >> /var/log/deuswatch-backup.log 2>&1
```

**Restore** (destructive - replaces the database; stops api/gateway/worker during the
load, follows the TimescaleDB pre/post-restore procedure, restarts them after):

```bash
./scripts/restore.sh backups/deuswatch-20260713-033000.sql.gz
```

What the dump covers: everything in Postgres - events/alerts, users & sessions, rules,
decoders, integrations (secrets stay encrypted - the same `SECRETS_KEY` must be set on
the restore target), tickets, dashboards, settings. What it does NOT cover:
`deploy/.env` (copy it separately, it holds the secrets) and `deploy/certs/` (regen with
certgen, then re-enroll agents, or copy the directory to keep the same CA).

**Test the restore path** once before you need it: run a backup, restore it on a scratch
machine, log in. A backup that has never been restored is a hope, not a backup.

## 6. Updating

```bash
./scripts/update.sh        # pull + rebuild; migrations auto-apply on api start
```

Check **Settings → Software updates** in the UI to see whether a newer release exists
(read-only compare against GitHub; the update itself always runs on the host - the web
app never controls Docker, by design).
