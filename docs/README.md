# Aegrail Docs

Aegrail is the product and binary name for the security audit and incident triage tool described in `../idea.md`.

## Current Documents

- [Architecture](architecture.md): module boundaries, runtime pipeline, storage strategy, and Ollama integration.
- [Distributed Architecture](distributed-architecture.md): Agent, DB Collector, Hub, inventory, and cross-host correlation model.
- [Implementation Plan](implementation-plan.md): phased delivery plan from repository foundation to reports.
- [Pantheon WordPress Monitoring Plan](platforms/pantheon-wordpress.md): planned support for Pantheon-hosted single WordPress and WordPress Multisite networks.
- [Browser Crawler And JavaScript Monitoring Plan](collectors/browser-crawler.md): static and rendered-page crawler direction for script inventory, tag managers, and JavaScript drift.
- [Tracker](tracker.md): living task board for MVP work.
- [Architecture Decision 0001](decisions/0001-modular-monolith.md): why the first implementation should be a modular monolith.
- [Architecture Decision 0002](decisions/0002-aegrail-binary-name.md): why the binary is named `aegrail`.
- [Architecture Decision 0003](decisions/0003-local-postgres18-pgvector.md): local PostgreSQL 18 and pgvector service choice.
- [Architecture Decision 0004](decisions/0004-pgx-and-goose.md): PostgreSQL driver and migration tool choice.
- [Architecture Decision 0005](decisions/0005-local-evidence-archive.md): local immutable evidence archive choice.
- [Architecture Decision 0006](decisions/0006-first-wave-target-modules.md): WordPress and PrestaShop first-wave target choice.
- [Architecture Decision 0007](decisions/0007-agent-hub-architecture.md): Agent plus Hub distributed architecture.
- [Architecture Decision 0008](decisions/0008-one-repo-multiple-runtime-apps.md): one repo structured as Local, Hub, Agent, and Collector apps.
- [Brand Assets](brand/README.md): existing visual identity and generated brand files.
- [Services](../services/README.md): local Docker services for development.

## Working Principles

- Deterministic detection comes before LLM analysis.
- Raw evidence is immutable and local by default.
- Sensitive fields are redacted before reports, exports, embeddings, or LLM calls.
- CLI and HTTP workflows must share the same runtime use-case packages.
- Modules such as PrestaShop, WordPress, Mautic, Yii2, and Laravel plug into the core without changing it.

## Documentation Discipline

- Keep `architecture.md` focused on durable boundaries and package responsibilities.
- Keep `distributed-architecture.md` focused on Agent, Collector, Hub, inventory, and correlation behavior.
- Keep `implementation-plan.md` focused on phases, current status, and exit criteria.
- Keep `tracker.md` as the task-level source of truth.
- Add or update an ADR when a decision changes the shape of the system.
