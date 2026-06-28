#!/usr/bin/env sh
# Update a deployed DeusWatch: pull the latest code and rebuild/restart the stack.
# Safe to re-run. Your deploy/.env and local demo data are gitignored, so they survive.
#
#   ./scripts/update.sh
set -e
cd "$(dirname "$0")/.."

echo "==> Pulling latest from GitHub"
git pull --ff-only

COMPOSE="deploy/docker-compose.yml"
echo "==> Rebuilding & restarting containers (migrations auto-apply on api start)"
if [ -f deploy/.env ]; then
  docker compose -f "$COMPOSE" --env-file deploy/.env up -d --build
else
  docker compose -f "$COMPOSE" up -d --build
fi

echo "==> Done. Now on:"
git log --oneline -1
