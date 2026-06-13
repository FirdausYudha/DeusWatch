# Generate bundel sertifikat mTLS DeusWatch (CA + server + client) ke folder ini.
# Argumen tambahan diteruskan ke certgen, mis: .\generate.ps1 --dns localhost,api.example
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Push-Location $root
try {
    go run ./cmd/certgen --out deploy/certs @args
} finally {
    Pop-Location
}
