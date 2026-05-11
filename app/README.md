# Aegrail App

This directory contains the Go module for the Aegrail CLI and runtime apps.

## Layout

```text
app/
  go.mod
  cmd/
    aegrail/
      main.go
  internal/
    bootstrap/   config, logger, and dependency wiring
    domain/      shared domain types and normalization helpers
    local/       local investigation workflows
    hub/         distributed inventory and signed ingest use cases
    agent/       per-server identity, queue, file watcher, and log tailer
    collector/   database and app collectors
    ports/       storage and integration interfaces
    adapters/    CLI, HTTP, PostgreSQL, filesystem, and future Ollama adapters
    modules/     WordPress, PrestaShop, and later target modules
    redaction/   secret and token redaction helpers
    reports/     report renderers
    rules/       deterministic rules and risk scoring
  migrations/
  configs/
  testdata/
```

The binary is named `aegrail`.

## Useful Commands

```powershell
go run ./cmd/aegrail --help
go run ./cmd/aegrail version
go run ./cmd/aegrail init --data-dir ../data
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail site add --name "Petlink Demo" --url https://petlink.example petlink
go run ./cmd/aegrail site list
$env:AEGRAIL_DATA_DIR="../data"
go run ./cmd/aegrail import files --site petlink --path testdata/evidence-sample/access.log
go run ./cmd/aegrail import logs --site petlink --path testdata/evidence-sample
go run ./cmd/aegrail inventory bootstrap single-site --kind wordpress --org acme --project customer-site --host web-01 --agent-id agt_web_01 --fingerprint SHA256:test
go run ./cmd/aegrail agent start --once --root /var/www/site --profile wordpress
go run ./cmd/aegrail agent start --once --log /var/log/nginx/access.log
go fmt ./...
go test ./...
```

## Rules

- Keep business logic out of CLI and HTTP handlers.
- Keep adapters replaceable through interfaces in `internal/ports`.
- Keep runtime-app responsibilities in `internal/local`, `internal/hub`, `internal/agent`, and `internal/collector`.
- Keep source-specific logic under `internal/modules`.
- Keep deterministic tests independent from Ollama.
