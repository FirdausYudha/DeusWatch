#!/bin/sh
# DeusWatch worker watchdog.
#
# Brings the worker back whatever happened to it. This exists because every in-container mechanism
# has a case it cannot cover:
#
#   restart: unless-stopped  -> only restarts a container that EXISTS and EXITED.
#   the in-process watchdog  -> only fires if the process is healthy enough to run a goroutine.
#   an autoheal container    -> only restarts UNHEALTHY containers, cannot recreate a missing one,
#                               and needs the Docker socket (root-equivalent) to do it.
#
# The gap they all share is the one that actually bit this deployment: a failed deploy left NO
# worker container at all, so there was nothing to restart and the stack sat dead until someone
# noticed. Running on the host as root, this covers missing, exited, restarting and unhealthy alike.
#
# It is deliberately dumb: check, log, recreate. No state, no retries of its own (the timer is the
# retry), and it never touches any other service.
set -eu

COMPOSE_DIR="${DEUSWATCH_DIR:-/home/deus/Document/DeusWatch/deploy}"
CONTAINER="${DEUSWATCH_WORKER_CONTAINER:-deuswatch-worker-1}"

cd "$COMPOSE_DIR" || { logger -t deuswatch-watchdog "cannot cd to $COMPOSE_DIR"; exit 1; }

state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo missing)
# Containers without a healthcheck report no Health block at all; treat that as "not unhealthy"
# rather than assuming the worst, so an older image does not cause a restart loop.
health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER" 2>/dev/null || echo none)

case "$state:$health" in
  running:healthy|running:none|running:starting)
    exit 0
    ;;
esac

logger -t deuswatch-watchdog "worker state=$state health=$health, bringing it back"
# `up -d` both recreates a missing container and restarts a dead one, which is why it is used here
# instead of `restart` (restart fails outright when the container does not exist).
if docker compose up -d worker >/dev/null 2>&1; then
  logger -t deuswatch-watchdog "worker recovered"
else
  logger -t deuswatch-watchdog "worker recovery FAILED, check: docker compose -f $COMPOSE_DIR/docker-compose.yml logs worker"
  exit 1
fi
