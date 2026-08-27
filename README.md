# pfsense-mssql-orchestrator

Rust service for applying pfSense REST API changes from desired state stored in
Microsoft SQL Server.

Target runtime: manual/on-demand launch from the user's desktop. The expected
workplace SQL Server is `srv-db`, database `rd_all`; the actual connection is
provided by a configured MSSQL connection string.

## Scope

- Read desired pfSense operations from MSSQL.
- Read new remote-work requests from `srv-db` / `rd_all`.
- Check approval completion through the request query's `por_neisp` flag.
- Map request authors to OpenVPN users and their own workstations.
- Grant OpenVPN-to-RDP access through pfSense API templates.
- Build deterministic operation hashes.
- Skip already-applied operations through local SQLite audit.
- Support `--dry-run` by default for safe inspection.
- Apply operations to pfSense REST API only when `run --apply` is used.
- Keep MSSQL and pfSense secrets out of git.

## Expected MSSQL Shape

There are two layers:

1. Source request query: [sql/remote_work_requests.sql](sql/remote_work_requests.sql)
   returns raw remote-work requests from the workplace MSSQL database.
2. Desired-state query: the later production query must return normalized
   pfSense operations.

The desired-state query must return these columns:

| Column | Required | Meaning |
|---|---:|---|
| `rule_key` | yes | stable business key for idempotency |
| `action` | yes | logical action name for logs/audit |
| `method` | yes | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `path` | yes | pfSense API path, for example `/firewall/rule` |
| `body_json` | no | JSON body for methods that need a payload |
| `desired_hash` | no | external state hash; if absent, the service hashes method/path/body |

See [docs/REMOTE_WORK_SQL_CONTRACT_RU.md](docs/REMOTE_WORK_SQL_CONTRACT_RU.md)
for the current source-query contract.

## Configuration

Copy `config.example.toml` to `config.toml` and set non-secret values.

Secrets are environment variables:

```sh
export MSSQL_CONNECTION_STRING='server=tcp:SQL_HOST,1433;database=DB;user=USER;password=PASSWORD;TrustServerCertificate=true'
export PFSENSE_API_TOKEN='...'
```

For this project the intended MSSQL target is:

```text
server=tcp:srv-db,1433;database=rd_all;...
```

Create a private `workstations.toml` from `workstations.example.toml`. It maps
the request author field `ot_kogo` to a pfSense/OpenVPN user and workstation
host/IP. Keep the private mapping out of git if it contains personal data.

## Commands

GUI mode is available for desktop use:

```sh
cargo run -- gui
```

The GUI edits non-secret settings, stores the MSSQL password and pfSense API
token in the operating system credential store, generates the runtime
`config.toml`, and starts the same `process-requests` workflow. Dry-run is
selected by default; enable APPLY only after reviewing the result.

```sh
cargo run -- plan --config config.toml
cargo run -- run --config config.toml --once --dry-run
cargo run -- run --config config.toml --once --apply
cargo run -- process-requests --config config.toml --once --dry-run
cargo run -- process-requests --config config.toml --once --apply
```

`--dry-run` is the operational default. `--apply` must be explicit.

`run` is the low-level desired-state mode. `process-requests` is the business
workflow for remote-work requests.

## Build

Local release build:

```sh
cargo build --release
```

GitHub Actions builds and publishes a Windows artifact named
`pfsense-mssql-orchestrator-windows-x86_64`.

## Safety Notes

- Do not run `--apply` until the SQL query returns a small, reviewed result set.
- Start with read-only pfSense endpoints or a lab pfSense instance.
- Verify from the desktop that SQL Server and pfSense API are reachable before
  the first real `process-requests --apply`.
- Current pfSense REST API base URL is expected to be
  `https://10.35.0.1:8443/api/v2`. From the laptop, HTTP/80 redirects there,
  but HTTPS/8443 currently times out through the SNB VPN path; validate from
  the desktop runtime host.
- Prefer a dedicated MSSQL login with read-only access to the desired-state view.
- Prefer a dedicated pfSense API token with the narrowest available privileges.
