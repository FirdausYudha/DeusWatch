#!/usr/bin/env sh
# Restore a DeusWatch database backup made by scripts/backup.sh.
#
#   ./scripts/restore.sh backups/deuswatch-20260713-033000.sql.gz
#
# DESTRUCTIVE: the current database is DROPPED and recreated from the dump. The
# stack's api/gateway/worker are stopped during the restore and restarted after.
# Follows the documented TimescaleDB flow (pre_restore -> load dump -> post_restore).
set -e
cd "$(dirname "$0")/.."

DUMP="$1"
if [ -z "$DUMP" ] || [ ! -f "$DUMP" ]; then
  echo "usage: ./scripts/restore.sh <dump-file.sql.gz>" >&2
  exit 1
fi

COMPOSE="deploy/docker-compose.yml"
[ -f deploy/.env ] && ENVFILE="--env-file deploy/.env" || ENVFILE=""

printf "This DROPS the current database and loads %s. Type 'yes' to continue: " "$DUMP"
read -r ANSWER
[ "$ANSWER" = "yes" ] || { echo "aborted"; exit 1; }

echo "==> Stopping services that hold DB connections"
docker compose -f "$COMPOSE" $ENVFILE stop api gateway worker

pg() { docker compose -f "$COMPOSE" $ENVFILE exec -T db psql -U deuswatch -q "$@"; }

echo "==> Recreating the database"
pg -d postgres -c "DROP DATABASE IF EXISTS deuswatch WITH (FORCE);"
pg -d postgres -c "CREATE DATABASE deuswatch OWNER deuswatch;"
pg -d deuswatch -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"

echo "==> Loading $DUMP (TimescaleDB pre/post restore mode)"
pg -d deuswatch -c "SELECT timescaledb_pre_restore();"
gunzip -c "$DUMP" | pg -d deuswatch
pg -d deuswatch -c "SELECT timescaledb_post_restore();"

echo "==> Restarting services"
docker compose -f "$COMPOSE" $ENVFILE start api gateway worker

echo "==> Restore complete."
