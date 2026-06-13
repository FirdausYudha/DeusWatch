#!/usr/bin/env sh
# Cross-compile agent DeusWatch untuk berbagai OS/arch ke dist/.
#   VERSION=v0.1.0 ./scripts/build-agent.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p dist

TARGETS="linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64"
for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"; ext=""
  [ "$os" = "windows" ] && ext=".exe"
  out="dist/deuswatch-agent-${os}-${arch}${ext}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/agent
  echo "built $out"
done
echo "Selesai. Biner agent ada di dist/."
