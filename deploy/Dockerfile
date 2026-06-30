# syntax=docker/dockerfile:1
#
# Generic Dockerfile for DeusWatch Go services. Select the binary via the CMD build-arg:
#   docker build --build-arg CMD=worker -f deploy/Dockerfile ..
# Used by compose for api / gateway / worker.

# ── Build stage ───────────────────────────────────────────
FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependency cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG CMD=api
# VERSION (short git commit) is baked in so the app can report its build + check for updates.
ARG VERSION=dev
# Static binary (CGO off) so it can run on the distroless static image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" -o /out/app ./cmd/${CMD}

# When building the api, also cross-compile the agent binaries it serves to endpoints
# via the one-line installer (GET /api/agent/binary/{os}/{arch}). /agents stays empty
# for the other services.
RUN mkdir -p /agents && if [ "$CMD" = "api" ]; then \
      for t in linux/amd64 linux/arm64 windows/amd64; do \
        os="${t%/*}"; arch="${t#*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"; \
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
          -o "/agents/deuswatch-agent-$os-$arch$ext" ./cmd/agent; \
      done; \
    fi

# ── Runtime stage ─────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
# Detection rules (used by the worker; ignored by other services).
COPY rules /rules
# Agent binaries served by the api's one-line installer (empty for other services).
COPY --from=build /agents /agents
USER nonroot:nonroot
ENTRYPOINT ["/app"]
