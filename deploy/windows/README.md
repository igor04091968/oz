# Windows Deployment

Target runtime: manual/on-demand launch from the user's desktop. Service mode is
optional and should only be enabled after the manual workflow is validated.

## Layout

```text
C:\Tools\OZ\oz.exe
C:\Tools\PfsenseMssqlOrchestrator\config.toml
C:\Tools\PfsenseMssqlOrchestrator\workstations.toml
C:\Tools\PfsenseMssqlOrchestrator\audit.sqlite3
```

## Environment

Set Machine-level variables:

```powershell
[Environment]::SetEnvironmentVariable("MSSQL_CONNECTION_STRING", "server=tcp:SQL_HOST,1433;database=DB_NAME;user=DB_USER;password=DB_PASSWORD;TrustServerCertificate=true", "Machine")
[Environment]::SetEnvironmentVariable("PFSENSE_API_TOKEN", "CHANGE_ME", "Machine")
[Environment]::SetEnvironmentVariable("RUST_LOG", "info", "Machine")
```

Restart the service process after changing environment variables.

## Install With NSSM

```powershell
.\install-nssm.ps1
nssm start PfsenseMssqlOrchestrator
```

The service is installed as manual start by default. Switch to automatic only
after `--once --dry-run` and one controlled `--once --apply` have been validated.

For normal desktop use, run manually instead:

```powershell
.\oz.exe process-requests --config .\config.toml --once --dry-run
.\oz.exe process-requests --config .\config.toml --once --apply
```
