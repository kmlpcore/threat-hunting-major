<#
.SYNOPSIS
  Windows equivalent of the Makefile (no `make` needed).

.EXAMPLE
  .\scripts\dev.ps1 up
  .\scripts\dev.ps1 ping
  .\scripts\dev.ps1 seed -RunId demo -Days 7 -Users 40
  .\scripts\dev.ps1 check
  .\scripts\dev.ps1 e2e
  .\scripts\dev.ps1 hunt       # M5: plan + run the Sigma corpus
  .\scripts\dev.ps1 feeds      # M7: pull TI feeds
  .\scripts\dev.ps1 history    # M8: 15-year layout
  .\scripts\dev.ps1 report     # M9: docs/evaluation.md
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet("env", "up", "down", "clean", "ping", "generate", "ingest", "seed", "check", "status", "test", "e2e", "logs",
                 "hunt", "feeds", "history", "retention", "drill", "fidelity", "report")]
    [string]$Target = "up",
    [string]$RunId = "demo",
    [int]$Days = 7,
    [int]$Users = 40
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Invoke-Checked {
    & $args[0] $args[1..($args.Count - 1)]
    if ($LASTEXITCODE -ne 0) { throw "failed ($LASTEXITCODE): $($args -join ' ')" }
}
function Cli { Invoke-Checked docker compose run --rm --no-deps cli @args }
function CliPython { Invoke-Checked docker compose run --rm --no-deps --entrypoint python cli @args }

switch ($Target) {
    "env"      { if (-not (Test-Path .env)) { Copy-Item .env.example .env; "created .env - edit the secrets" } }
    "up"       { & $PSCommandPath env; Invoke-Checked docker compose up -d --build --wait }
    "down"     { Invoke-Checked docker compose down }
    "clean"    { Invoke-Checked docker compose down -v }
    "ping"     { Cli ping }
    "generate" { Cli generate --run-id $RunId --days $Days --users $Users }
    "ingest"   { Cli ingest --run-id $RunId }
    "seed"     { Cli generate --run-id $RunId --days $Days --users $Users; Cli ingest --run-id $RunId }
    "check"    { Cli ecs-check; CliPython -m benchmarks.ground_truth_check --run-id $RunId }
    "status"   { (Invoke-WebRequest -UseBasicParsing http://localhost:8001/partitions/summary).Content }
    "test"     { CliPython -m pytest -q tests }
    "e2e"      { Invoke-Checked docker compose run --rm --no-deps -e E2E=1 --entrypoint python cli -m pytest -q tests/e2e }
    "logs"     { docker compose logs --tail 100 }
    "hunt"     { Cli hunt rules/sigma }
    "feeds"    { Cli feeds }
    "history"  { Cli history --years 15 }
    "retention" { Cli retention apply }
    "drill"    { Cli retention drill }
    "fidelity" { CliPython -m benchmarks.fidelity --run-id $RunId }
    "report"   { CliPython -m benchmarks.report --run-id $RunId --feeds }
}
