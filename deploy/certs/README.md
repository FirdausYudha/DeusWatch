# Sertifikat mTLS

Folder ini menampung bundel sertifikat mTLS DeusWatch. **Berkas sertifikat tidak
pernah di-commit** (lihat `.gitignore`) — hanya script generator yang masuk repo.

## Generate

```sh
# Linux / macOS
./generate.sh

# Windows (PowerShell)
.\generate.ps1
```

Atau langsung:

```sh
go run ./cmd/certgen --out deploy/certs
```

## Hasil

| Berkas | Isi |
|---|---|
| `ca.crt` / `ca.key` | Root CA self-signed DeusWatch |
| `server.crt` / `server.key` | Sertifikat server (gateway/api), SAN: localhost, gateway, api, 127.0.0.1, ::1 |
| `client.crt` / `client.key` | Sertifikat client (agent) |

Server dikonfigurasi `RequireAndVerifyClientCert` (mTLS penuh, TLS 1.3 minimum) —
client tanpa sertifikat sah ditolak pada handshake. Lihat `internal/mtls`.

> Untuk produksi, kunci CA sebaiknya disimpan terpisah/aman dan sertifikat client
> diterbitkan per-agent saat enrollment (lihat design doc bagian 4 & 12).
