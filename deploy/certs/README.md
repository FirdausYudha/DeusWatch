# mTLS certificates

This folder holds the DeusWatch mTLS certificate bundle. **Certificate files are never
committed** (see `.gitignore`) - only the generator scripts go in the repo.

## Generate

```sh
# Linux / macOS
./generate.sh

# Windows (PowerShell)
.\generate.ps1
```

Or directly:

```sh
go run ./cmd/certgen --out deploy/certs
```

## Output

| File | Contents |
|---|---|
| `ca.crt` / `ca.key` | DeusWatch self-signed root CA |
| `server.crt` / `server.key` | Server cert (gateway/api), SAN: localhost, gateway, api, 127.0.0.1, ::1 |
| `client.crt` / `client.key` | Client cert (agent) |

The server is configured with `RequireAndVerifyClientCert` (full mTLS, TLS 1.3 minimum) -
a client without a valid certificate is rejected at the handshake. See `internal/mtls`.

> In production the CA key should be stored separately/securely and client certs should
> be issued per-agent at enrollment time (see design doc sections 4 & 12).
