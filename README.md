# Aegrail

Aegrail is a local-first monitoring and incident-triage system for WordPress, PrestaShop, and PHP application estates.

It runs agents near the sites, sends signed evidence to a Hub, turns deterministic rules into findings, and gives an operator dashboard for answering one practical question: is something wrong, where is it, and what evidence proves it?

![Aegrail overview](./docs/banner.png)

## Current Shape

- `app/` contains the Go `aegrail` binary: Hub, Agent, collectors, CLI, reports, rules, storage adapters, and migrations.
- `dashboard/` contains the React dashboard served by Vite in development or by the Hub in production-like local runs.
- `services/` contains local infrastructure, currently PostgreSQL 18 with pgvector.
- `data/` is reserved for local runtime output and is not the place for committed fixtures or docs.
- `docs/README.md` is the single maintained product, architecture, runbook, and tracker document.

## Quick Start

```powershell
docker compose -f services/compose.yaml up -d postgres18
cd app
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail --help
go test ./...
```

Dashboard development:

```powershell
cd dashboard
npm install
npm run dev
```

The maintained documentation lives here:

- [Aegrail Documentation](docs/README.md)
- [App README](app/README.md)
- [Dashboard README](dashboard/README.md)
- [Services README](services/README.md)
- [Brand Assets](docs/brand/README.md)
