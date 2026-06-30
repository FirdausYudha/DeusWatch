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
# Bake the commit into the build so the UI's "check for update" knows what's running.
export DEUSWATCH_VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
echo "==> Rebuilding & restarting containers (version=$DEUSWATCH_VERSION; migrations auto-apply on api start)"
if [ -f deploy/.env ]; then
  docker compose -f "$COMPOSE" --env-file deploy/.env up -d --build
else
  docker compose -f "$COMPOSE" up -d --build
fi

echo "==> Done. Now on:"
git log --oneline -1
