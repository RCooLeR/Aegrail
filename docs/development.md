# Development Notes

## Go Apps

`hub/` and `agent/` are separate Go modules, joined for local development by the root `go.work`. They intentionally duplicate the small shared domain/redaction surface for now so each app can evolve without a hidden shared runtime dependency.

`hub/` owns:

- Hub APIs, ingest, inventory, findings, deployments, allowlists, reports, users, and dashboard serving
- deterministic rules, correlation, risk scoring, and fixture evaluation
- PostgreSQL migrations and storage adapters
- Hub CLI commands for local development and operations

`agent/` owns:

- Agent config, file/log/database/browser collection, local state, queueing, and replay
- WordPress, PrestaShop, and Mautic module/profile helpers used by the agent
- Agent CLI commands for local development and operations

Package map:

```text
hub/cmd/hub/                 Hub app entrypoint
hub/internal/adapters/       Hub CLI, HTTP, PostgreSQL, model adapters
hub/internal/bootstrap/      Hub config, logger, database wiring
hub/internal/hub/            inventory, ingest, correlation, findings, reports, users
hub/internal/reports/        JSON, Markdown, CSV, and evidence bundle renderers
hub/migrations/              SQL migrations
hub/configs/                 Hub config examples

agent/cmd/agent/             Agent app entrypoint
agent/internal/agent/        agent runtime, config, queue, file watch, log watch
agent/internal/collector/    database and browser collectors
agent/internal/modules/      WordPress, PrestaShop, and Mautic source logic
agent/internal/redaction/    secret and token redaction
agent/configs/               Agent YAML examples
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
cd agent
go test ./...

cd ..\hub
go test ./...

cd ..\dashboard
npm run build
```

## Documentation Maintenance

- Root `README.md` is only a short intro, banner, quick links, and license pointer.
- Maintained docs live in `docs/`.
- If behavior changes, update the matching doc and the tracker.
- If a topic becomes too large, add a named file under `docs/` and link it from `docs/README.md`.
