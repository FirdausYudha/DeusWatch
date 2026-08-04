# syntax=docker/dockerfile:1
#
# Multi-target Dockerfile for DeusWatch Go services.
#
#   docker build --target runtime-static --build-arg CMD=api     -f deploy/Dockerfile ..
#   docker build --target runtime-cgo    --build-arg CMD=gateway -f deploy/Dockerfile ..
#
# Two runtime targets exist because the gateway now links against libyara for manager-side YARA
# scanning on FIM snapshot uploads (needs CGO + libyara.so at runtime), while api/worker/certgen
# stay as CGO-free static distroless images (smaller, no shared-library surface, no bloat).

# ── Common builder (git for pseudo-versions, module cache) ────
FROM golang:1.26-alpine AS builder-common
WORKDIR /src
# git is required by `go mod download` to resolve pseudo-versions the module proxy can't serve
# directly. ca-certificates covers the HTTPS fetches Go performs against those origins.
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD=api
# VERSION (short git commit) is baked in so the app can report its build + check for updates.
ARG VERSION=dev

# ── Static build (CGO off) ──────────────────────────────────
# Produces a pure-Go binary suitable for distroless static. The yara package's nocgo stub is picked
# by build tags in this configuration, so a static build silently disables YARA scanning.
FROM builder-common AS build-static
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" -o /out/app ./cmd/${CMD}
# When building the api, also cross-compile the agent binaries it serves to endpoints via the
# one-line installer (GET /api/agent/binary/{os}/{arch}). /agents stays empty for other services.
RUN mkdir -p /agents && if [ "$CMD" = "api" ]; then \
      for t in linux/amd64 linux/arm64 windows/amd64; do \
        os="${t%/*}"; arch="${t#*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"; \
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" \
          -o "/agents/deuswatch-agent-$os-$arch$ext" ./cmd/agent; \
      done; \
    fi

# ── CGO build (libyara-linked, for the gateway) ─────────────
# libyara-dev provides the yara headers + libyara.so the Go binding links against.
FROM builder-common AS build-cgo
RUN apk add --no-cache gcc musl-dev yara-dev pkgconfig
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" -o /out/app ./cmd/${CMD}
RUN mkdir -p /agents

# ── Static runtime (api/worker/certgen) ─────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime-static
COPY --from=build-static /out/app /app
# Detection rules (used by the worker; ignored by other services).
COPY rules /rules
# Custom decoders (used by the gateway to normalize log sources without a built-in decoder).
COPY decoders /decoders
# Agent binaries served by the api's one-line installer (empty for other services).
COPY --from=build-static /agents /agents
USER nonroot:nonroot
ENTRYPOINT ["/app"]

# ── CGO runtime (gateway) ───────────────────────────────────
# Alpine + libyara + ca-certificates. libyara.so must be present at runtime for the linked binary
# to start; adding it here means the operator gets YARA out of the box with no host-side install.
FROM alpine:3.20 AS runtime-cgo
RUN apk add --no-cache yara ca-certificates && \
    addgroup -S dw && adduser -S -G dw dw
COPY --from=build-cgo /out/app /app
COPY rules /rules
COPY decoders /decoders
COPY --from=build-cgo /agents /agents
USER dw:dw
ENTRYPOINT ["/app"]
