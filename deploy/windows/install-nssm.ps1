param(
    [string]$InstallDir = "C:\Program Files\PfsenseMssqlOrchestrator",
    [string]$ConfigPath = "C:\ProgramData\PfsenseMssqlOrchestrator\config.toml",
    [string]$ServiceName = "PfsenseMssqlOrchestrator"
)

$ErrorActionPreference = "Stop"

$ExePath = Join-Path $InstallDir "pfsense-mssql-orchestrator.exe"

if (-not (Get-Command nssm.exe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found in PATH"
}

if (-not (Test-Path $ExePath)) {
    throw "Executable not found: $ExePath"
}

if (-not (Test-Path $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}

nssm install $ServiceName $ExePath run --config $ConfigPath
nssm set $ServiceName AppDirectory $InstallDir
nssm set $ServiceName AppStopMethodConsole 15000
nssm set $ServiceName Start SERVICE_DEMAND_START

Write-Host "Installed $ServiceName. Set machine environment variables before starting:"
Write-Host "  MSSQL_CONNECTION_STRING"
Write-Host "  PFSENSE_API_TOKEN"
Write-Host "Then run: nssm start $ServiceName"
