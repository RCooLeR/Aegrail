# Developer Experience

## Goals

Aegrail should be easy to run, easy to test, easy to reason about, and hard to accidentally break.

Developer setup should require:

- Go
- Docker
- PostgreSQL service from `services`
- Ollama only for AI workflows
- browser executable only for rendered crawler tests
- Node.js only for dashboard workflows
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
dashboard/                 TypeScript React dashboard
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
- risk scoring metadata
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
- admin request anomaly fixture
- web request traffic and Tor fixture
- WordPress administrator role change fixture
- PrestaShop module drift fixture
- PrestaShop employee privilege escalation fixture
- browser script injection fixture
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
go run ./cmd/aegrail report hub-findings --org acme --project customer-site --env production --format markdown --output ..\data\reports\hub-findings.md
go run ./cmd/aegrail report hub-findings --org acme --project customer-site --env production --format manager-markdown --output ..\data\reports\manager-summary.md
go run ./cmd/aegrail report timeline --org acme --project customer-site --env production --since 24h --format csv --output ..\data\reports\timeline.csv
go run ./cmd/aegrail report evidence-bundle --org acme --project customer-site --env production --limit 20 --output ..\data\reports\evidence-bundle.json
go run ./cmd/aegrail analyze model status
go run ./cmd/aegrail analyze model prompt --prompt "Return exactly: aegrail-ok"
go run ./cmd/aegrail analyze model embed --text "Aegrail evidence"
go run ./cmd/aegrail analyze model report --org acme --project customer-site --env production --limit 20 --save --output ..\data\reports\model-analysis.json
go run ./cmd/aegrail report model-analysis list --org acme --project customer-site --env production
go run ./cmd/aegrail report model-analysis show --org acme --project customer-site --env production --id <report-id>
go test ./...
```

Multi-site command:

```powershell
go run ./cmd/aegrail agent config validate --config configs/agent.multi-site.yaml.example
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example --once
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example --once --bootstrap
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example --once --bootstrap --discard-pending
go run ./cmd/aegrail agent status --config configs/agent.multi-site.yaml.example
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
- JSON, Markdown, manager summary, and CSV timeline report preview
- redacted evidence bundle preview
- model gateway status, prompt, embedding smoke tests, saved model report history, and prompt-versioned advisory analysis report preview

## Documentation Rule

Every module should document:

- what it owns
- what it does not own
- key inputs and outputs
- failure behavior
- config it depends on
- tests that protect it

This keeps Aegrail maintainable as it grows from CLI-first tool into distributed monitoring platform.
