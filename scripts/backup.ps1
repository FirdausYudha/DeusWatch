# Back up the DeusWatch database on Windows to a compressed dump (stack keeps running).
# Keeps the newest $env:BACKUP_KEEP dumps (default 14) and prunes older ones.
#   .\scripts\backup.ps1 [output-dir]      # default: .\backups
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$outDir = if ($args.Count -ge 1) { $args[0] } else { 'backups' }
$keep = if ($env:BACKUP_KEEP) { [int]$env:BACKUP_KEEP } else { 14 }
$compose = 'deploy/docker-compose.yml'
$envArgs = @(); if (Test-Path deploy/.env) { $envArgs = @('--env-file', 'deploy/.env') }

New-Item -ItemType Directory -Force $outDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$file = Join-Path $outDir "deuswatch-$stamp.sql.gz"

# Dump to a file INSIDE the container, then docker-cp it out: PowerShell's `>`
# re-encodes native stdout as text and would corrupt the gzip stream.
Write-Host "==> Dumping database to $file"
docker compose -f $compose @envArgs exec -T db sh -c 'pg_dump -U deuswatch -d deuswatch --no-owner | gzip > /tmp/deuswatch-backup.sql.gz'
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed (exit $LASTEXITCODE)" }
docker compose -f $compose @envArgs cp db:/tmp/deuswatch-backup.sql.gz $file
if ($LASTEXITCODE -ne 0) { throw "copy out of the container failed (exit $LASTEXITCODE)" }
docker compose -f $compose @envArgs exec -T db rm -f /tmp/deuswatch-backup.sql.gz

$size = '{0:N1} MB' -f ((Get-Item $file).Length / 1MB)
Write-Host "==> Done: $file ($size)"

Get-ChildItem $outDir -Filter 'deuswatch-*.sql.gz' | Sort-Object LastWriteTime -Descending |
  Select-Object -Skip $keep | ForEach-Object {
    Write-Host "==> Pruning old backup: $($_.FullName)"
    Remove-Item $_.FullName -Force
  }
