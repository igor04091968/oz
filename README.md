# pfsense-mssql-orchestrator

Rust service for applying pfSense REST API changes from desired state stored in
Microsoft SQL Server.

Target installation host: `WS-GST01`. The application does not assume the
developer laptop VPN route at runtime. SQL Server connectivity is provided by a
configured MSSQL connection string on the workstation.

## Scope

- Read desired pfSense operations from MSSQL.
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

On Windows, set these as Machine-level environment variables or inject them
through the service wrapper used on `WS-GST01`.

## Commands

```sh
cargo run -- plan --config config.toml
cargo run -- run --config config.toml --once --dry-run
cargo run -- run --config config.toml --once --apply
```

`--dry-run` is the operational default. `--apply` must be explicit.

## Safety Notes

- Do not run `--apply` until the SQL query returns a small, reviewed result set.
- Start with read-only pfSense endpoints or a lab pfSense instance.
- Verify from `WS-GST01` that SQL Server and pfSense API are reachable before
  enabling the scheduled/service mode.
- Prefer a dedicated MSSQL login with read-only access to the desired-state view.
- Prefer a dedicated pfSense API token with the narrowest available privileges.
