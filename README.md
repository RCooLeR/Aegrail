# Aegrail

Aegrail is an evidence-first monitoring and incident triage platform for WordPress, PrestaShop, and PHP application estates.

It is built around one `aegrail` binary, local agents, a central Hub, CMS-aware collectors, deterministic findings, browser JavaScript monitoring, and reports grounded in stored evidence.

![Aegrail overview](./docs/banner.png)

## Documentation

- [Product Vision](docs/01_PRODUCT_VISION.md)
- [Architecture](docs/02_ARCHITECTURE.md)
- [Domain Model](docs/03_DOMAIN_MODEL.md)
- [Evidence Collection](docs/04_EVIDENCE_COLLECTION.md)
- [Detection And Correlation](docs/05_DETECTION_AND_CORRELATION.md)
- [AI And LLM Strategy](docs/06_AI_AND_LLM_STRATEGY.md)
- [Operations And Security](docs/07_OPERATIONS_AND_SECURITY.md)
- [Delivery Plan](docs/08_DELIVERY_PLAN.md)
- [Developer Experience](docs/09_DEVELOPER_EXPERIENCE.md)

Supporting specs:

- [Agent Multi-Site Configuration](docs/configuration/agent-multi-site.md)
- [Browser Crawler And JavaScript Monitoring](docs/collectors/browser-crawler.md)
- [Dashboard API Pointer](docs/dashboard.md)
- [Pantheon WordPress Monitoring](docs/platforms/pantheon-wordpress.md)
- [Tracker](docs/tracker.md)
- [Architecture Decisions](docs/decisions)
- [Brand Assets](docs/brand/README.md)
- [Local Services](services/README.md)

## Core Principles

- Evidence-first: collect and store deterministic evidence before generating analysis.
- Modular: Local, Hub, Agent, Collector, Dashboard, rules, reports, and AI are separate modules.
- Distributed: every event carries org, project, environment, app, service, host, agent, region, and labels where known.
- CMS-aware: WordPress and PrestaShop are first-wave targets, with Mautic, Yii2, and Laravel planned later.
- Explainable: findings must cite rules, versions, event context, and evidence refs.
- Offline tolerant: agents queue locally and replay when the Hub is reachable.
- Secure by default: secrets are redacted before reports, dashboard views, embeddings, or LLM prompts.
- Local-first AI: Ollama can summarize evidence, but deterministic rules remain the source of truth.

## Quick Start

```powershell
docker compose -f services/compose.yaml up -d postgres18
cd app
go run ./cmd/aegrail --help
go run ./cmd/aegrail db migrate
go test ./...
```

See [Developer Experience](docs/09_DEVELOPER_EXPERIENCE.md) for local commands and test strategy.
