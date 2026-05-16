# Development Notes

## App Module

`app/` is the Go module for the Aegrail Hub and Agent binaries.

It owns:

- Hub APIs, ingest, inventory, findings, deployments, allowlists, reports, users, and dashboard serving
- Agent config, file/log/database/browser collection, local state, queueing, and replay
- deterministic rules, correlation, risk scoring, and fixture evaluation
- PostgreSQL migrations and storage adapters
- CLI commands for local development and operations

Package map:

```text
cmd/aegrail/             combined compatibility binary entrypoint
cmd/aegrail-agent/       Agent binary entrypoint
cmd/aegrail-hub/         Hub binary entrypoint
internal/adapters/       CLI, HTTP, PostgreSQL, browser, model adapters
internal/agent/          agent runtime, config, queue, file watch, log watch
internal/bootstrap/      config, logger, database wiring
internal/collector/      database and browser collectors
internal/domain/         shared domain types
internal/hub/            inventory, ingest, correlation, findings, reports, users
internal/modules/        WordPress and PrestaShop source logic
internal/ports/          storage and integration interfaces
internal/redaction/      secret and token redaction
internal/reports/        JSON, Markdown, CSV, and evidence bundle renderers
migrations/              SQL migrations
configs/                 local examples only; never put real secrets here
```

## Standards

- Business logic belongs in Hub, Agent, Collector, report, and module packages, not CLI or HTTP glue.
- Redaction should happen before dashboard responses, reports, evidence bundles, or model prompts.
- Deterministic tests must not require Ollama.
- Dashboard UI should read Hub APIs only.
- Keep docs generic. Use example domains and paths only.
- Do not add one-off markdown files outside `docs/`.

## Verification

```powershell
cd app
go test ./...

cd ..\dashboard
npm run build
```

## Documentation Maintenance

- Root `README.md` is only a short intro, banner, quick links, and quick start.
- Maintained docs live in `docs/`.
- If behavior changes, update the matching doc and the tracker.
- If a topic becomes too large, add a named file under `docs/` and link it from `docs/README.md`.
