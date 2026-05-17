# Hub

The Hub is the central API and storage app. It receives encrypted Agent evidence, stores inventory and events in PostgreSQL, runs deterministic rules, exposes dashboard APIs, manages users/2FA, and generates reports/model analysis.

## Docs

- [Install](install.md): database, environment, migrations, and local run commands.
- [How It Works](how-it-works.md): ingest, storage, rules, findings, reports, and model-analysis flow.
- [Agent API](agent-api.md): encrypted Agent ingest and provisioning contract.
- [Dashboard API](dashboard-api.md): authenticated dashboard endpoints.
- [Tracker](tracker.md): Hub status, next work, and later work.

## Code

```text
hub/cmd/hub/                 Hub app entrypoint.
hub/configs/                 Hub environment example.
hub/migrations/              PostgreSQL migrations.
hub/internal/adapters/http/  HTTP router and dashboard static serving.
hub/internal/adapters/postgres/ PostgreSQL repositories.
hub/internal/adapters/redis/ Redis-backed queues and locks.
hub/internal/hub/            Ingest, inventory, rules, findings, reports, users.
hub/internal/reports/        JSON, Markdown, CSV, evidence bundles.
```

## Main Commands

```powershell
cd hub
go run ./cmd/hub --help
go run ./cmd/hub db migrate
go run ./cmd/hub serve --dashboard-dir ..\dashboard\dist
go run ./cmd/hub findings list --org acme --project customer-site --env production --app main-web
go run ./cmd/hub model-analysis queue --limit 5
```
