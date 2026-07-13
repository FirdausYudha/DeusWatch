# Restore a DeusWatch database backup (made by backup.ps1/backup.sh) on Windows.
#   .\scripts\restore.ps1 backups\deuswatch-20260713-033000.sql.gz
# DESTRUCTIVE: the current database is DROPPED and recreated from the dump.
# Follows the documented TimescaleDB flow (pre_restore -> load dump -> post_restore).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($args.Count -lt 1 -or -not (Test-Path $args[0])) {
  Write-Error 'usage: .\scripts\restore.ps1 <dump-file.sql.gz>'
}
$dump = $args[0]
$compose = 'deploy/docker-compose.yml'
$envArgs = @(); if (Test-Path deploy/.env) { $envArgs = @('--env-file', 'deploy/.env') }

$answer = Read-Host "This DROPS the current database and loads $dump. Type 'yes' to continue"
if ($answer -ne 'yes') { Write-Host 'aborted'; exit 1 }

function Invoke-Pg([string]$db, [string]$sql) {
  docker compose -f $compose @envArgs exec -T db psql -U deuswatch -q -d $db -c $sql
  if ($LASTEXITCODE -ne 0) { throw "psql failed (exit $LASTEXITCODE): $sql" }
}

Write-Host '==> Stopping services that hold DB connections'
docker compose -f $compose @envArgs stop api gateway worker

Write-Host '==> Recreating the database'
Invoke-Pg 'postgres' 'DROP DATABASE IF EXISTS deuswatch WITH (FORCE);'
Invoke-Pg 'postgres' 'CREATE DATABASE deuswatch OWNER deuswatch;'
Invoke-Pg 'deuswatch' 'CREATE EXTENSION IF NOT EXISTS timescaledb;'

# Copy the dump INTO the container and load it there (binary-safe on PowerShell).
Write-Host "==> Loading $dump (TimescaleDB pre/post restore mode)"
docker compose -f $compose @envArgs cp $dump db:/tmp/deuswatch-restore.sql.gz
if ($LASTEXITCODE -ne 0) { throw "copy into the container failed (exit $LASTEXITCODE)" }
Invoke-Pg 'deuswatch' 'SELECT timescaledb_pre_restore();'
docker compose -f $compose @envArgs exec -T db sh -c 'gunzip -c /tmp/deuswatch-restore.sql.gz | psql -U deuswatch -q -d deuswatch'
if ($LASTEXITCODE -ne 0) { throw "restore failed (exit $LASTEXITCODE)" }
Invoke-Pg 'deuswatch' 'SELECT timescaledb_post_restore();'
docker compose -f $compose @envArgs exec -T db rm -f /tmp/deuswatch-restore.sql.gz

Write-Host '==> Restarting services'
docker compose -f $compose @envArgs start api gateway worker

Write-Host '==> Restore complete.'
