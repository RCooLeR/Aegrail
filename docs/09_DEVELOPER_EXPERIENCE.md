# Developer Experience

## Goals

Aegrail should be easy to run, easy to test, easy to reason about, and hard to accidentally break.

Developer setup should require:

- Go
- Docker
- PostgreSQL service from `services`
- Ollama only for AI workflows
- browser executable only for rendered crawler tests
- one environment file for local defaults

## Repository Shape

Current and planned structure:

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
dashboard/                 planned TypeScript React dashboard
docs/                      product, architecture, operation, and delivery docs
services/                  local Docker services
data/                      local runtime data, ignored by Git
```

## Coding Principles

- Keep business rules out of CLI and HTTP handlers.
- Keep SQL access in PostgreSQL adapter/repository modules.
- Keep runtime app responsibilities explicit: Local, Hub, Agent, Collector, Dashboard.
- Keep source-specific logic under modules and collectors.
- Keep redaction close to normalization and before reports/prompts.
- Prefer explicit structs over loosely typed maps at service boundaries.
- Prefer small interfaces for storage, model, queue, and collector dependencies.
- Keep generated AI text separate from deterministic findings.
- Keep deterministic tests independent from Ollama.

## Testing Strategy

Unit tests:

- redaction
- event normalization
- file severity classification
- watch path resolution
- log parsing
- config validation
- rule scoring
- finding dedupe
- browser script observation parsing

Integration tests:

- clean database migration
- inventory bootstrap
- signed Hub ingest
- agent queue replay
- file watch baseline and diff
- log tail baseline and diff
- Hub correlation save/list
- browser crawl ingest with fixtures or fake browser path where practical

Evaluation tests:

- clean WordPress fixture
- compromised WordPress fixture
- generic suspicious file path fixture
- clean PrestaShop fixture
- compromised PrestaShop fixture
- browser script drift fixture
- deployment-window false positive fixture
- multi-host file drift fixture

Current fixture command:

```powershell
go run ./cmd/aegrail hub rules evaluate --fail-on-mismatch
```

## Local Commands

Useful commands:

```powershell
docker compose -f services/compose.yaml up -d postgres18
cd app
go run ./cmd/aegrail --help
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail inventory bootstrap single-site --kind wordpress --org acme --project customer-site --host web-01 --agent-id agt_web_01 --fingerprint SHA256:test
go run ./cmd/aegrail hub serve
go run ./cmd/aegrail agent status
go run ./cmd/aegrail agent start --once --root /var/www/site --profile wordpress
go run ./cmd/aegrail collector browser crawl --url https://example.com --rendered --wait-tag-manager --timeout 30s --format json
go run ./cmd/aegrail hub rules evaluate --fail-on-mismatch
go test ./...
```

Multi-site command:

```powershell
go run ./cmd/aegrail agent config validate --config configs/agent.multi-site.yaml.example
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example --once
```

## Debugging Tools

Developers and operators need:

- agent queue status
- queue batch viewer
- Hub ingest batch list
- event timeline query
- finding detail view
- rule explanation output
- browser script baseline and allowlist inspector
- file baseline comparison
- config coverage report
- report preview
- model prompt preview

## Documentation Rule

Every module should document:

- what it owns
- what it does not own
- key inputs and outputs
- failure behavior
- config it depends on
- tests that protect it

This keeps Aegrail maintainable as it grows from CLI-first tool into distributed monitoring platform.
