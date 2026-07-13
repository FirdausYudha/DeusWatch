#!/usr/bin/env sh
# Back up the DeusWatch database to a compressed dump (safe while the stack runs).
# Keeps the last BACKUP_KEEP dumps (default 14) and prunes older ones.
#
#   ./scripts/backup.sh [output-dir]        # default: ./backups
#   BACKUP_KEEP=30 ./scripts/backup.sh /mnt/nas/deuswatch
#
# Restore with:  ./scripts/restore.sh <dump-file>
# Cron example (daily 03:30):
#   30 3 * * *  cd /path/to/DeusWatch && ./scripts/backup.sh >> /var/log/deuswatch-backup.log 2>&1
set -e
cd "$(dirname "$0")/.."

OUT_DIR="${1:-backups}"
KEEP="${BACKUP_KEEP:-14}"
COMPOSE="deploy/docker-compose.yml"
[ -f deploy/.env ] && ENVFILE="--env-file deploy/.env" || ENVFILE=""

mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
FILE="$OUT_DIR/deuswatch-$STAMP.sql.gz"

echo "==> Dumping database to $FILE"
# pg_dump runs inside the db container; custom-format would need pg_restore, plain SQL
# keeps the restore path simple (psql) and diffs/compresses well.
docker compose -f "$COMPOSE" $ENVFILE exec -T db \
  pg_dump -U deuswatch -d deuswatch --no-owner | gzip > "$FILE"

SIZE="$(du -h "$FILE" | cut -f1)"
echo "==> Done: $FILE ($SIZE)"

# Prune: keep the newest $KEEP dumps.
COUNT=0
for f in $(ls -1t "$OUT_DIR"/deuswatch-*.sql.gz 2>/dev/null); do
  COUNT=$((COUNT + 1))
  if [ "$COUNT" -gt "$KEEP" ]; then
    echo "==> Pruning old backup: $f"
    rm -f "$f"
  fi
done
