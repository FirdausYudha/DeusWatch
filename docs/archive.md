# Raw daily log archive (zstd)

DeusWatch can keep a **compressed raw archive** of everything it ingests — the LST Tameng
"Lapis 2" raw archive. Every event that reaches the pipeline is appended to a file laid out by
source and log type, one file per day:

```
<ARCHIVE_DIR>/<source>/<dataset>/<YYYY-MM-DD>.log.zst
   e.g.  opnsense-a/modsecurity/2026-07-17.log.zst
         wazuh-agent_web01/sshd/2026-07-17.log.zst
```

- **source** = the sending agent / host (the dashboard's Agent value).
- **dataset** = the log type (`modsecurity`, `sshd`, `web`, `syslog`, …).
- Each file holds the **raw original lines** (or the normalized JSON for structured events that
  have no original text, e.g. FIM / Windows).

This is the "log super kaya siap jual" (rich sellable log) source: a faithful, cheap-to-store
copy of the raw telemetry, separate from the queryable enriched events in the database.

## Enable

Set `ARCHIVE_DIR` in the worker's environment and **mount it as a volume** so it persists:

```dotenv
# deploy/.env
ARCHIVE_DIR=/archive
ARCHIVE_FLUSH=10s          # how often buffered lines are written (default 10s)
ARCHIVE_RETENTION_DAYS=0   # delete files older than N days; 0 = keep forever
```

```yaml
# deploy/docker-compose.yml — worker service
  worker:
    # …
    volumes:
      - ./archive:/archive        # or a dedicated disk/NAS for long retention
```

Apply: `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker`. The log
shows `worker: raw archive active (/archive, retention=0d)`.

## Read it back

The files are standard zstd — concatenated frames, which any zstd reader decompresses
transparently:

```bash
zstd -dc /archive/opnsense-a/modsecurity/2026-07-17.log.zst | less
# or grep straight through it
zstdgrep 'id "942' /archive/opnsense-a/modsecurity/2026-07-17.log.zst
```

## Notes

- Storage is separate from the database retention (`docs/storage.md`) — the archive is raw text,
  the DB holds enriched/queryable events. Point `ARCHIVE_DIR` at a big/cheap disk for long keep.
- Writes are append-only zstd frames, flushed every `ARCHIVE_FLUSH`, so a crash only loses the
  last unsynced buffer — never a whole file.
- Source/dataset names are sanitized into safe path segments (no traversal), so an attacker
  can't steer a write outside `ARCHIVE_DIR` via a crafted agent name.
