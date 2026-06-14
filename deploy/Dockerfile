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
# Static binary (CGO off) so it can run on the distroless static image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# ── Runtime stage ─────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
# Detection rules (used by the worker; ignored by other services).
COPY rules /rules
USER nonroot:nonroot
ENTRYPOINT ["/app"]
