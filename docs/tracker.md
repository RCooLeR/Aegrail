# Aegrail Tracker

Status: active
Last updated: 2026-05-12

## Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Done
- `[?]` Needs decision

## Phase 0: Product Foundation

- [x] Preserve original product sketch in `idea.md`.
- [x] Create `docs`, `app`, `data`, and `services` workspace areas.
- [x] Choose final product and binary name: `aegrail`.
- [x] Choose modular monolith as the initial implementation style.
- [x] Keep one repo with Local, Hub, Agent, Collector, and future Dashboard runtime apps.
- [x] Add local PostgreSQL 18 with pgvector service.
- [x] Choose `pgx` and `goose`.
- [x] Add canonical numbered docs spine.
- [?] Decide credential encryption approach for local deployments.
- [?] Decide whether scheduled Hub jobs live in the main binary or a separate worker command.

## Phase 1: Hub And Agent Foundation

- [x] Create Go module and `cmd/aegrail/main.go`.
- [x] Add zerolog initialization.
- [x] Add urfave/cli command groups.
- [x] Add chi HTTP health routing.
- [x] Add PostgreSQL migrations and repositories.
- [x] Add distributed inventory tables.
- [x] Add deployment marker tables.
- [x] Add Hub ingest event batch tables.
- [x] Add distributed Hub findings table.
- [x] Add `aegrail inventory` command group.
- [x] Add `aegrail hub`, `agent`, and `collector` command groups.
- [x] Add signed `POST /api/v1/ingest/events`.
- [x] Add agent install/status/enqueue/send.
- [x] Add agent filesystem watcher loop.
- [x] Add WordPress and PrestaShop file watch profiles.
- [x] Add agent log tail watcher loop.
- [x] Add structured Nginx, Apache, and PHP log parsers.
- [x] Add Hub event ingest storage.
- [x] Add cross-host app file baseline comparison.
- [x] Add deterministic Hub correlation findings.
- [x] Add JSON Hub finding export.

## Phase 2: Multi-Site Agent Configuration

- [x] Document server-level multi-site agent config.
- [x] Add `app/configs/agent.multi-site.yaml.example`.
- [x] Add config schema structs for `aegrail.agent.server_config.v1`.
- [x] Add YAML config loader.
- [x] Add config validation rules.
- [x] Add `aegrail agent config validate`.
- [x] Add per-site app/service/label context to queued events.
- [x] Add per-site file watch state paths.
- [x] Add per-site log tail state paths.
- [x] Add per-site database snapshot state paths.
- [x] Add `aegrail agent run --config ... --once`.
- [x] Add continuous multi-site agent runner.
- [ ] Report config coverage to Hub.
- [x] Run database collectors from multi-site agent config.
- [x] Run browser crawls from multi-site agent config.

## Phase 3: WordPress And PrestaShop Evidence

- [x] Prioritize WordPress and PrestaShop as first-wave target modules.
- [x] Add WordPress module spec package.
- [x] Add PrestaShop module spec package.
- [x] Document Pantheon WordPress and Multisite monitoring.
- [~] Add WordPress DB snapshot importer or collector.
- [x] Snapshot redacted WordPress users.
- [x] Snapshot redacted WordPress usermeta capabilities.
- [~] Snapshot WordPress options.
- [~] Snapshot WordPress active plugins and themes.
- [~] Snapshot WordPress cron tasks.
- [x] Emit redacted WordPress DB snapshot diff events.
- [x] Detect new WordPress administrators.
- [x] Detect changed WordPress capabilities.
- [~] Detect suspicious WordPress option values.
- [~] Detect new or changed WordPress plugins/themes.
- [~] Add PrestaShop DB snapshot importer or collector.
- [x] Snapshot redacted PrestaShop employees.
- [x] Snapshot PrestaShop modules.
- [~] Snapshot PrestaShop configuration.
- [~] Snapshot PrestaShop tabs, hooks, and access.
- [x] Emit redacted PrestaShop DB snapshot diff events.
- [x] Detect new PrestaShop employees and SuperAdmin accounts.
- [~] Detect suspicious PrestaShop configuration values.
- [x] Detect suspicious PrestaShop module changes.

## Phase 4: Detection Quality And Correlation

- [x] Persist deterministic findings.
- [x] Deduplicate Hub correlation findings.
- [x] Add browser script drift findings from Hub event history.
- [x] Add browser script allowlist review workflow.
- [x] Add DB snapshot diff findings from Hub event history.
- [ ] Define rule interface and registry.
- [ ] Define versioned rule metadata.
- [ ] Add generic suspicious path rules.
- [ ] Add admin request anomaly rules.
- [ ] Add traffic spike rules.
- [ ] Add risk scoring.
- [ ] Add finding status lifecycle.
- [ ] Add finding-to-allowlist handoff command.
- [ ] Add deployment-aware scoring.
- [ ] Add fixture-based rule evaluation sets.

## Phase 5: Hub API And Dashboard

- [x] Document dashboard information architecture and API direction.
- [ ] Add Hub read API for inventory.
- [ ] Add Hub read API for events/timeline.
- [ ] Add Hub read API for findings.
- [ ] Add Hub read API for agents and config coverage.
- [ ] Add Hub read API for deployments.
- [ ] Add Hub read API for browser script observations.
- [ ] Create `dashboard/` TypeScript React Bootstrap app.
- [ ] Build Overview view.
- [ ] Build Findings and Finding Detail views.
- [ ] Build Timeline view.
- [ ] Build Inventory, Sites, and Agents views.
- [ ] Build Browser Scripts view.
- [ ] Add finding acknowledge and false-positive actions.
- [ ] Add browser script allowlist actions.

## Phase 6: Reports And AI

- [x] Add JSON findings export.
- [ ] Add Markdown technical report.
- [ ] Add Markdown manager summary.
- [ ] Add CSV timeline export.
- [ ] Add report renderer golden tests.
- [ ] Add Ollama model gateway.
- [ ] Add configurable investigation model.
- [ ] Add configurable embedding model.
- [ ] Build compact redacted evidence bundles.
- [ ] Store prompt template version with LLM reports.
- [ ] Support offline AI mode.
- [ ] Add fake model adapter for tests.

## Phase 7: Remote Collection And Scheduling

- [x] Add static browser crawler for script inventory.
- [x] Add rendered browser crawl mode with bounded waits.
- [x] Emit browser crawl observations into Hub event storage.
- [ ] Add SSH/SFTP collector.
- [~] Add MySQL read-only collector.
- [ ] Add Pantheon provider collector for SFTP logs and DB snapshots.
- [ ] Add Pantheon WordPress Multisite network inventory and snapshot support.
- [ ] Add scheduled daily health reports.
- [ ] Add scheduled browser crawls.
- [ ] Add PostgreSQL-backed or Redis/NATS-backed Hub job queue.
- [ ] Add Slack, Teams, or email alerts.

## Phase 8: Scale And Operations

- [ ] Add per-agent secrets or mTLS.
- [ ] Add dashboard authentication.
- [ ] Add dashboard roles.
- [ ] Add dashboard action audit log.
- [ ] Add backup and restore playbook.
- [ ] Add retention policy.
- [ ] Add metrics and tracing.
- [ ] Add object storage option for larger evidence archives.

## Secondary PHP Targets

- [ ] Add Mautic module spec.
- [ ] Add Yii2 module spec.
- [ ] Add Laravel module spec.
- [ ] Extract reusable PHP framework file/config/session heuristics.
