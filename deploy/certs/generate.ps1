# Generate the DeusWatch mTLS certificate bundle (CA + server + client) into this folder.
# Extra arguments are forwarded to certgen, e.g.: .\generate.ps1 --dns localhost,api.example
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Push-Location $root
try {
    go run ./cmd/certgen --out deploy/certs @args
} finally {
    Pop-Location
}
