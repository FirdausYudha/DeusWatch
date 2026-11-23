# Mirroring your log volume

DeusWatch keeps your telemetry in two places you may want to copy off the box: the **raw compressed
archive** (faithful original lines, cheap to store) and the **queryable events** in the database.
This page is about getting a second copy of them onto a NAS or an offsite location with ordinary
tools, so a dead disk or a lost server does not take your logs with it.

## What there is to mirror

| Source | What it holds | Where | Doc |
|---|---|---|---|
| Raw archive | the original log lines, **already compressed** (zstd), one file per source/dataset/day | `ARCHIVE_DIR` (e.g. `/archive`) | docs/archive.md |
| Queryable events | enriched, searchable events (30-day retention, columnar-compressed) | the Postgres/Timescale volume | docs/storage.md |
| Analytics mirror | enriched events in ClickHouse, for fast long-history analytics | your ClickHouse | docs/clickhouse.md |

For "mirror my logs", the **raw archive is the one to copy**: it is append-only, already compressed,
and safe to copy while the system runs. The database is a different problem (see the warning below).

## Step 1: turn on the archive

If you have not already, enable it so there is something to mirror (see docs/archive.md):

```dotenv
# deploy/.env
ARCHIVE_DIR=/archive
ARCHIVE_FLUSH=10s
ARCHIVE_RETENTION_DAYS=0   # 0 = keep forever; set a number if the mirror is your long-term copy
```

```yaml
# deploy/docker-compose.yml, worker service
  worker:
    volumes:
      - ./archive:/archive
```

The archive writes append-only zstd frames flushed every `ARCHIVE_FLUSH`. Yesterday's files never
change again, which is what makes every method below safe: a copy is consistent, at worst missing the
last few seconds still in the flush buffer.

## Step 2: mirror the archive volume

Pick whichever fits what you already run. They are not exclusive.

### A. Point the archive straight at a NAS (live mirror)

Mount an NFS/SMB share and make it the archive volume, so every write lands on the NAS as it happens:

```yaml
  worker:
    volumes:
      - type: volume
        source: archive-nas
        target: /archive
volumes:
  archive-nas:
    driver_opts:
      type: nfs
      o: "addr=192.168.1.10,nfsvers=4,rw"
      device: ":/export/deuswatch-archive"
```

Simplest when you have a NAS already. The trade-off is that a NAS outage stalls archive writes, so
keep a small local fallback or use method B instead for loose coupling.

### B. Periodic sync with rsync + cron (NAS or offsite)

Because old files are immutable, rsync only ever moves new data:

```bash
# /etc/cron.hourly/deuswatch-archive-mirror  (make it executable)
#!/bin/sh
rsync -a --delete-after /archive/ nas:/volume1/deuswatch-archive/
```

Drop `--delete-after` if the mirror should keep files longer than the source's
`ARCHIVE_RETENTION_DAYS`. Add `-z` only if the link is slow: the files are already compressed, so
rsync compression buys little and costs CPU.

### C. Continuous folder sync (Syncthing)

Point a Syncthing folder at `/archive` and share it with another machine or NAS for near-real-time
replication without cron. Set the archive side to "send only" so a change on the mirror can never
propagate back.

### D. Encrypted, deduplicated offsite backup (restic / borg)

For an offsite copy with history and encryption rather than a plain mirror:

```bash
restic -r s3:https://s3.example.com/deuswatch-archive backup /archive
restic -r s3:https://s3.example.com/deuswatch-archive forget --keep-daily 30 --prune
```

restic and borg deduplicate and encrypt, so an untrusted destination (cloud bucket, rented box) is
fine. Run it from cron like method B.

### E. Filesystem-level replication (ZFS / btrfs)

If `/archive` lives on ZFS or btrfs, use the filesystem's own snapshots and `zfs send | zfs recv`
(or `btrfs send`) to replicate to another pool or host. This gives you point-in-time snapshots on top
of the mirror.

## Mirroring the queryable database (do this differently)

Do **not** file-copy or rsync a live Postgres data directory: you get a torn, unusable copy. To
replicate the searchable events, use a database method instead:

- **Streaming replication** to a standby Postgres (hot standby you can also read from), or
- **`pg_basebackup`** plus WAL archiving for a restorable base backup, or
- **logical dumps** on a schedule for a smaller, portable copy.

Or sidestep it: enable the **ClickHouse mirror** (docs/clickhouse.md) so a second, independent store
already holds every enriched event, and mirror ClickHouse's storage with its own tooling.

## What to run

A common, low-effort setup:

- Archive on (compressed raw logs), `ARCHIVE_DIR` mirrored to a NAS by method A or B.
- An offsite copy of the archive with restic (method D) for disaster recovery.
- For queryable history: a Postgres standby, or ClickHouse, depending on whether you need SQL search
  or analytics.

See also docs/scaling.md (handling thousands of agents) and docs/storage.md (retention and sizing).
