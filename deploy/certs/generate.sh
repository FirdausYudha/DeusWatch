#!/usr/bin/env sh
# Generate the DeusWatch mTLS certificate bundle (CA + server + client) into this folder.
# Extra arguments are forwarded to certgen, e.g.: ./generate.sh --dns localhost,api.example
set -e
cd "$(dirname "$0")/../.."
go run ./cmd/certgen --out deploy/certs "$@"
