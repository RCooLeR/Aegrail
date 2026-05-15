# Aegrail App

This is the Go module for the `aegrail` binary.

It owns:

- Hub APIs, ingest, inventory, findings, reports, users, and dashboard serving
- Agent config, file/log/database/browser collection, local state, queueing, and replay
- deterministic rules, correlation, risk scoring, and fixture evaluation
- PostgreSQL migrations and storage adapters
- CLI commands for local development and operations

Useful commands:

```powershell
go run ./cmd/aegrail --help
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail hub serve
go run ./cmd/aegrail hub serve --dashboard-dir ..\dashboard\dist
go run ./cmd/aegrail agent config validate --config configs/agent.multi-site.example.yaml
go run ./cmd/aegrail agent run --config configs/agent.multi-site.example.yaml --once --bootstrap
go run ./cmd/aegrail hub rules evaluate --fail-on-mismatch
go test ./...
```

Package map:

```text
cmd/aegrail/             binary entrypoint
internal/adapters/       CLI, HTTP, PostgreSQL, filesystem, browser, model adapters
internal/agent/          agent runtime, config, queue, file watch, log watch
internal/bootstrap/      config, logger, database wiring
internal/collector/      database and browser collectors
internal/domain/         shared domain types
internal/hub/            inventory, ingest, correlation, findings, reports, users
internal/local/          local/manual investigation workflows
internal/modules/        WordPress and PrestaShop source logic
internal/ports/          storage and integration interfaces
internal/redaction/      secret and token redaction
internal/reports/        JSON, Markdown, CSV, and evidence bundle renderers
migrations/              SQL migrations
configs/                 local examples only; never put real secrets here
```

The maintained architecture and tracker live in [../docs/README.md](../docs/README.md).
