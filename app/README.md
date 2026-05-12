# Aegrail App

This directory contains the Go module for the `aegrail` binary and runtime apps.

## Runtime Apps

- Local: local imports, investigation, and reports.
- Hub: signed ingest, inventory, timelines, findings, reports, and dashboard APIs.
- Agent: per-server monitoring, local queueing, file watching, log tailing, and planned multi-site config.
- Collector: database, browser, and provider-specific collection.

## Layout

```text
app/
  cmd/aegrail/             binary entrypoint
  internal/adapters/       CLI, HTTP, PostgreSQL, filesystem, browser, future AI adapters
  internal/agent/          agent identity, queue, file watch, log watch, multi-site runtime
  internal/bootstrap/      config, logger, database wiring
  internal/collector/      browser, database, platform collector orchestration
  internal/domain/         shared domain types
  internal/hub/            inventory, ingest, baselines, correlation, findings
  internal/local/          local import and investigation workflows
  internal/modules/        WordPress, PrestaShop, later Mautic/Yii2/Laravel
  internal/ports/          storage and integration interfaces
  internal/redaction/      secret and token redaction
  internal/reports/        report renderers
  internal/rules/          deterministic rules and scoring
  migrations/              SQL migrations
  configs/                 env and agent config examples
  testdata/                fixtures
```

## Useful Commands

```powershell
go run ./cmd/aegrail --help
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail inventory bootstrap single-site --kind wordpress --org acme --project customer-site --host web-01 --agent-id agt_web_01 --fingerprint SHA256:test
go run ./cmd/aegrail hub serve
go run ./cmd/aegrail hub findings list --org acme --project customer-site --env production --app main-web
go run ./cmd/aegrail agent status
go run ./cmd/aegrail agent start --once --root /var/www/site --profile wordpress
go run ./cmd/aegrail agent start --once --log /var/log/nginx/access.log
go run ./cmd/aegrail collector browser crawl --url https://example.com --rendered --wait-tag-manager --timeout 30s --format json
go test ./...
```

Planned multi-site runtime:

```powershell
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example --once
```

## Rules

- Keep business logic out of CLI and HTTP handlers.
- Keep adapters replaceable through interfaces in `internal/ports`.
- Keep runtime-app responsibilities in `internal/local`, `internal/hub`, `internal/agent`, and `internal/collector`.
- Keep source-specific logic under `internal/modules`.
- Keep deterministic tests independent from Ollama.

See [Developer Experience](../docs/09_DEVELOPER_EXPERIENCE.md) for the broader engineering guide.
