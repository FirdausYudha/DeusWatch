# Log storage - lifecycle, remote DB, replication & alerts

DeusWatch stores all logs/events in **PostgreSQL + TimescaleDB**. This guide covers how to
control where logs live, how old data is aged out, how to get a near-full alert, and how to
run replication - plus the **Log Storage** panel on the dashboard.

> A note on "ILM": DeusWatch is relational (PostgreSQL), not Elasticsearch. The equivalent of
> Elasticsearch ILM here is **TimescaleDB retention + compression**: old data is compressed,
> then automatically dropped past the retention window. This is safer than swapping volumes
> (no risk of corrupting a relational database) and is the standard PostgreSQL approach.

---

## 1. The dashboard "Log Storage" panel

The dashboard shows three cards, refreshed every few seconds (`GET /api/storage/status`):

- **Database size** - current DB size, event count, and (if a budget is set) a usage bar.
  The host line shows which server the DB lives on (e.g. `db`, or Server B's address).
- **Lifecycle** - the active retention window and compression threshold.
- **Replication** - `active` (green) when a standby is streaming, with the standby address;
  `not configured` otherwise.

---

## 2. Near-full alert + usage bar

Set a soft budget so DeusWatch can show a usage bar and warn you before the disk fills.
In `deploy/.env`:

```dotenv
# Soft cap for the log DB. Enables the usage bar + near-full notifications.
STORAGE_BUDGET_GB=50
# Alert when usage crosses this percent (default 85). Sent once per day.
STORAGE_ALERT_PERCENT=85
```

The worker checks hourly and, when usage crosses the threshold, sends a message to your
configured channels (Telegram/email - see [notifications.md](notifications.md)). Apply with:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker api
```

> No budget set = no usage bar and no near-full alert (size is still shown). The retention
> policy still ages out old data regardless, so the DB does not grow unbounded.

---

## 3. Lifecycle: retention + compression (the "ILM")

Defaults (from migration `000001`): chunks are **1 day**, compressed after **7 days**
(~90% smaller, still queryable), and **dropped after 30 days**.

**From the UI (easiest):** **Settings → Log storage lifecycle** — set "keep logs for (days)"
and "compress after (days)"; the worker applies the new TimescaleDB policies immediately.

To change it from SQL instead, connect to the DB and re-apply the policy. Example - keep 90 days:

```sql
SELECT remove_retention_policy('events', if_exists => true);
SELECT add_retention_policy('events', INTERVAL '90 days');
```

To change the **compression threshold** (e.g. compress after 3 days):

```sql
SELECT remove_compression_policy('events', if_exists => true);
SELECT add_compression_policy('events', INTERVAL '3 days');
```

Run against the running DB, e.g.:

```bash
docker exec -i deuswatch-db-1 psql -U deuswatch -d deuswatch -c \
  "SELECT add_retention_policy('events', INTERVAL '90 days');"
```

The new window appears in the dashboard **Lifecycle** card on the next refresh.

---

## 4. Store logs on a separate server (Server B)

Run the manager on Server A and the log database on Server B by pointing DeusWatch at Server
B's PostgreSQL. You can either drop the bundled `db` service and use an external DB, or keep
`db` only on Server B. The app needs the DSN in two places (api + worker).

On **Server B**: run PostgreSQL 16 with the TimescaleDB extension, create the `deuswatch`
database/user, and allow Server A to connect (`listen_addresses`, `pg_hba.conf`, firewall on
`5432`).

On **Server A** (`deploy/.env`):

```dotenv
# Point both api and worker at Server B. sslmode=require recommended over a network.
DATABASE_URL=postgres://deuswatch:STRONG_PASSWORD@server-b.example:5432/deuswatch?sslmode=require
STORE_DSN=postgres://deuswatch:STRONG_PASSWORD@server-b.example:5432/deuswatch?sslmode=require
```

Then bring up the manager without the local DB:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d api gateway worker web
```

Migrations auto-apply on API start, so the schema is created on Server B automatically. The
dashboard **Database size** card will show Server B's host.

---

## 5. Replication (high availability)

PostgreSQL **streaming replication** keeps a hot standby in sync. It is configured at the
PostgreSQL layer (not by the app); DeusWatch then shows its status on the dashboard.

Outline (primary = Server B, standby = Server C):

1. **Primary** `postgresql.conf`: `wal_level = replica`, `max_wal_senders = 10`,
   `wal_keep_size = 512MB`. Create a replication role:
   ```sql
   CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'REPL_PASSWORD';
   ```
   Allow the standby in `pg_hba.conf`:
   ```
   host replication replicator <standby-ip>/32 scram-sha-256
   ```
   Reload: `SELECT pg_reload_conf();`
2. **Standby**: take a base backup and start streaming:
   ```bash
   pg_basebackup -h server-b.example -U replicator -D /var/lib/postgresql/data -Fp -Xs -P -R
   ```
   `-R` writes the standby connection settings; start PostgreSQL and it streams.
3. **Verify** on the primary:
   ```sql
   SELECT client_addr, state FROM pg_stat_replication;
   ```
   When a row shows `state = streaming`, the dashboard **Replication** card turns green
   ("active") and lists the standby.

For automatic failover, layer Patroni or repmgr on top - out of scope here, but the same
`pg_stat_replication` status drives the dashboard either way.

---

## Quick reference

| Goal | Where |
|---|---|
| Usage bar + near-full alert | `STORAGE_BUDGET_GB`, `STORAGE_ALERT_PERCENT` in `deploy/.env` |
| Keep logs longer/shorter | `add_retention_policy('events', INTERVAL '<n> days')` |
| Compress sooner/later | `add_compression_policy('events', INTERVAL '<n> days')` |
| Logs on another server | `DATABASE_URL` + `STORE_DSN` -> Server B |
| High availability | PostgreSQL streaming replication (status on dashboard) |
