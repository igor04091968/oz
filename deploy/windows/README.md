# Windows Deployment

Target runtime: manual/on-demand launch from the user's desktop. Service mode is
optional and should only be enabled after the manual workflow is validated.

## Layout

```text
C:\Tools\OZ\oz.exe
C:\Tools\OZ\config.toml
C:\Tools\OZ\audit.sqlite3
```

## Environment

Set Machine-level variables:

```powershell
[Environment]::SetEnvironmentVariable("MSSQL_CONNECTION_STRING", "server=tcp:SQL_HOST,1433;database=DB_NAME;user=DB_USER;password=DB_PASSWORD;TrustServerCertificate=true", "Machine")
[Environment]::SetEnvironmentVariable("RUST_LOG", "info", "Machine")
```

Restart the service process after changing environment variables.

## Local voice requirement

If the GUI setting `sip_audio_file` is empty, OZ generates the announcement
locally through the Windows Speech API. The workstation must have a local
Russian Windows voice package installed, for example `Microsoft Irina Desktop`:

`Settings -> Time & language -> Speech -> Voices`

Internet access is not required during synthesis or playback. If the Russian
voice package is unavailable, configure a compatible uncompressed PCM WAV file
instead (`16-bit`, `mono`, `8` or `16 kHz`).

## Install With NSSM

```powershell
.\install-nssm.ps1
nssm start OZ
```

The service is installed as manual start by default. Switch to automatic only
after the one-shot inspection workflow has been validated.

For normal desktop use, run manually instead:

```powershell
.\oz.exe process-requests --config .\config.toml
```
