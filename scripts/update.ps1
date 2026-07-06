# Update a deployed DeusWatch on Windows: pull latest code and rebuild/restart the stack.
# Safe to re-run. deploy/.env and local demo data are gitignored, so they survive.
#   .\scripts\update.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host "==> Pulling latest from GitHub"
git pull --ff-only

$compose = "deploy/docker-compose.yml"
# Bake the semantic version (nearest git tag, e.g. v1.1.1) into the build so the UI's
# "check for update" shows a real version, not a commit hash.
$env:DEUSWATCH_VERSION = (git describe --tags --always)
Write-Host "==> Rebuilding & restarting containers (version=$($env:DEUSWATCH_VERSION); migrations auto-apply on api start)"
if (Test-Path deploy/.env) {
  docker compose -f $compose --env-file deploy/.env up -d --build
} else {
  docker compose -f $compose up -d --build
}

Write-Host "==> Done. Now on:"
git log --oneline -1
