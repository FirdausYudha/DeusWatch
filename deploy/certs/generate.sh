#!/usr/bin/env sh
# Generate bundel sertifikat mTLS DeusWatch (CA + server + client) ke folder ini.
# Argumen tambahan diteruskan ke certgen, mis: ./generate.sh --dns localhost,api.example
set -e
cd "$(dirname "$0")/../.."
go run ./cmd/certgen --out deploy/certs "$@"
