# syntax=docker/dockerfile:1
#
# Dockerfile generik untuk service Go DeusWatch. Pilih biner lewat build-arg CMD:
#   docker build --build-arg CMD=worker -f deploy/Dockerfile ..
# Dipakai compose untuk api / gateway / worker.

# ── Build stage ───────────────────────────────────────────
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache layer dependensi.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG CMD=api
# Binary statis (CGO off) agar bisa jalan di image distroless static.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# ── Runtime stage ─────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
# Rule deteksi (dipakai worker; abaikan untuk service lain).
COPY rules /rules
USER nonroot:nonroot
ENTRYPOINT ["/app"]
