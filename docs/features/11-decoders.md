# 11. Decoders

Data-driven log parsing - the DeusWatch equivalent of Wazuh decoders. A decoder supports a **new
log source without writing code**: a regex extracts fields from a dataset's raw lines, and rules
scoped to the category you set then fire on it.

> New here? The end-to-end walkthrough (agent source -> decoder -> test -> rule -> ban) is in
> [docs/new-log-source.md](../new-log-source.md).

## How it works

- A decoder is a **Go RE2 regex** with **named capture groups** (`?P<source_ip>...`) that map to
  DCS fields, plus a static `category` / `action` / `outcome` / `level`. The full raw line is
  always kept as `event.original`, so keyword rules still work.
- Decoders run in the **gateway**, only as a **fallback** for datasets with no built-in decoder
  (sshd, web, firewall, fim, windows, suricata are built in). They are **compiled once and
  indexed by dataset**, so a line only tries the decoders for its own dataset - one linear-time
  regex per line (RE2 is ReDoS-safe).
- Stored in the `decoders` table, **seeded from the bundled `decoders/`** on first start; the
  gateway **live-reloads** the enabled set (~30s), so UI edits apply without a restart.

## How to use

- **Decoders** menu → table (name, dataset, category, regex, status). Toggle / Edit / Delete.
- **Add**: set the agent source **dataset**, a **category** (so rules can scope to it), and the
  **regex**. Named groups: `source_ip`, `source_port`, `destination_ip`, `destination_port`,
  `user_name`, `host_name`, `process_name`, `process_command_line`, `file_path`.
- **Test against real log lines** (the answer to "how do I know my raw lines?"):
  1. **Load recent lines** for the dataset - pulls real `event.original` samples from your own
     ingested logs.
  2. Click a line (or paste one) → **Test** shows whether it matched and **which fields** were
     extracted. Iterate on the regex before saving.
- Then add a rule under **Rules** scoped to that category, point an agent at the log (a source
  whose `dataset` matches), and the decoder + rule work together.

## Bundled database decoders

Six are shipped as seeds, turning a failed database login into `event.category: authentication`
plus `event.outcome: failure` with `source.ip` and `user.name` pulled out:

| File | Dataset | Log |
|---|---|---|
| `decoders/postgresql.yml` | `postgresql` | `/var/log/postgresql/postgresql-*.log` |
| `decoders/mysql.yml` | `mysql` | `/var/log/mysql/error.log` |
| `decoders/mariadb.yml` | `mariadb` | `/var/log/mysql/error.log` |
| `decoders/clickhouse.yml` | `clickhouse` | `/var/log/clickhouse-server/clickhouse-server.err.log` |
| `decoders/mongodb.yml` | `mongodb` | `/var/log/mongodb/mongod.log` |
| `decoders/mssql.yml` | `mssql` | SQL Server `ERRORLOG`, or the Windows Application log |

**No new rule is needed.** The brute-force aggregations in `rules/sigma/agg/` select on the
category, not on the dataset, so `auth_fail_by_ip` (more than 20 failures from one address in 5
minutes) and `auth_fail_by_user` (more than 15 against one account) start counting database logins
the moment the agent ships them. Point an agent at the log with a source whose `dataset` matches
the table above and that is the whole setup.

### Each engine needs its own logging turned on first

A decoder cannot read a line the database never wrote, and most of these are quiet by default.

| Engine | Required setting | Without it |
|---|---|---|
| PostgreSQL | `log_line_prefix = '%m [%p] %q%u@%d %h '` | Failures are logged, but with **no client address**. `auth_fail_by_user` fires, `auth_fail_by_ip` never does, and nothing can be banned. |
| MySQL 8 | `log_error_verbosity = 3` | "Access denied" is not written at all. |
| MariaDB | `log_warnings = 2` | Same. |
| SQL Server | Login auditing set to failed logins | Same. |
| MongoDB | none | Logs the address by default. |
| ClickHouse | none | Logs the failure, but **not** the address: it is on a separate Debug line, and a decoder sees one line at a time. For addresses, query `system.session_log` instead. |

The PostgreSQL row is the one that catches people. `%h` is absent from the Debian and Ubuntu
defaults, and the only message that carries the address regardless is the `pg_hba.conf` rejection,
which is why the decoder matches that one separately.

### What they deliberately do not do

They match failures only, never a successful login, so normal application traffic cannot be counted
into a brute-force alert. The consequence is that "brute force that eventually succeeded" is not a
signal DeusWatch raises today: it would need a rule correlating a success against the same account
right after a burst, which the aggregation syntax does not express.

They also leave a non-IPv4 host out of `source.ip` rather than storing it. MySQL writes
`'root'@'localhost'` for a local connection and SQL Server writes `[CLIENT: <local machine>]`;
putting either in the field the ban path reads as an address is worse than leaving it empty.

`internal/ingest/decoder_seeds_test.go` holds a real log line for every case in both tables above.
A decoder that stops matching is otherwise silent, which is exactly how the imported Wazuh drafts
in `decoders/wazuh-imported/` sat unused: they carry an empty `category`, nothing references them,
and that directory is not loaded (the seed scan is non-recursive).

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/decoders` / `POST /api/decoders` | list / create | `manage_rules` |
| `PUT /api/decoders/{id}` / `DELETE /api/decoders/{id}` | edit-toggle / delete | `manage_rules` |
| `GET /api/decoders/samples?dataset=` | recent raw lines for a dataset | `manage_rules` |
| `POST /api/decoders/test` | try a regex on one line, see extracted fields | `manage_rules` |

Frontend: [`web/src/decoders/`](../../web/src/decoders/). Backend:
[`internal/decoders/`](../../internal/decoders/), engine
[`internal/ingest/decoder.go`](../../internal/ingest/decoder.go). Bundled seeds +
format: [`decoders/`](../../decoders/README.md).

## Ports / tech

- Browser → Web `9173` → API `9080`. The **gateway** applies decoders during normalization.
  Language: Go (RE2), React/TypeScript (UI). Stored in PostgreSQL.

## Variables

- `DECODERS_DIR` (gateway/api env, default `/decoders`) - where the bundled seed decoders live
  (baked into the image). Everything else is DB-backed and edited live in the UI.

## Converting Wazuh decoders (optional, local)

`tools/wazuh2decoder` converts Wazuh XML decoders into **draft** DeusWatch decoders (translating
os_regex to RE2). Output is gitignored (Wazuh is GPLv2) and every draft must be reviewed and
**tested** here before enabling. See [`tools/wazuh2decoder/`](../../tools/wazuh2decoder/README.md).
