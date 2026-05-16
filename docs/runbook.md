# Local Runbook

## PostgreSQL

Start PostgreSQL 18 with pgvector:

```powershell
docker compose -f services/compose.yaml up -d postgres18
```

Default local connection string:

```text
postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable
```

Default local settings:

```text
host: localhost
port: 55432
database: aegrail
user: aegrail
password: aegrail
```

The Compose service uses a pgvector PostgreSQL image and enables required extensions from:

```text
services/postgres18/initdb/001_extensions.sql
```

Stop services:

```powershell
docker compose -f services/compose.yaml down
```

Remove the local database volume:

```powershell
docker compose -f services/compose.yaml down -v
```

This service is for local development only. Do not place real customer data in committed service configs.

## Hub

Run migrations:

```powershell
cd app
go run ./cmd/aegrail-hub db migrate
```

Start Hub:

```powershell
go run ./cmd/aegrail-hub hub serve --dashboard-dir ..\dashboard\dist
```

## Agent

Validate config:

```powershell
cd app
go run ./cmd/aegrail-agent agent config validate --config configs/agent.multi-site.example.yaml
```

Capture current state as baseline without creating detection noise:

```powershell
go run ./cmd/aegrail-agent agent run --config configs/agent.multi-site.example.yaml --once --bootstrap
```

Run one normal scan:

```powershell
go run ./cmd/aegrail-agent agent run --config configs/agent.multi-site.example.yaml --once
```

Run continuously:

```powershell
go run ./cmd/aegrail-agent agent run --config configs/agent.multi-site.example.yaml
```

`cmd/aegrail` remains as a combined compatibility binary, but new operational scripts should prefer `cmd/aegrail-hub` and `cmd/aegrail-agent`.

## Useful CLI Commands

```powershell
go run ./cmd/aegrail-hub --help
go run ./cmd/aegrail-hub inventory bootstrap single-site --kind wordpress --org acme --project customer-site --host web-01 --agent-id agt_web_01 --fingerprint SHA256:test
go run ./cmd/aegrail-hub hub findings list --org acme --project customer-site --env production --app main-web
go run ./cmd/aegrail-hub hub rules evaluate --fail-on-mismatch
go run ./cmd/aegrail-hub hub model-analysis queue --limit 5
go run ./cmd/aegrail-hub report hub-findings --org acme --project customer-site --env production --format markdown --output ..\data\reports\hub-findings.md
go run ./cmd/aegrail-hub report timeline --org acme --project customer-site --env production --since 24h --format csv --output ..\data\reports\timeline.csv
go run ./cmd/aegrail-agent module list
go test ./...
```

## Dashboard Operator Flows

- Browser script noise: open Browser Scripts, review the new domain/hash/tag-manager ID, then allowlist it when it is expected.
- File noise: open the issue detail, use the file ignore action for a narrow directory, and verify the node config coverage still shows a reasonable ignore list.
- Initial safe state: use the baseline action for first-scan findings or run the agent with `--bootstrap` before normal monitoring.
- Deployment noise: open Deployments, choose the node and timeframe, review the overlapping open alerts/warnings, then confirm the deployment marker.
- 2FA: Settings -> Users & 2FA -> Enroll, scan the QR, enter the current code, and activate.

## Local Data

The `data/` directory is for local runtime output and private investigation artifacts.

Examples:

- imported evidence
- agent snapshots
- generated reports
- exported evidence bundles
- temporary debugging files

Everything in `data/` should be treated as sensitive and kept out of Git.
