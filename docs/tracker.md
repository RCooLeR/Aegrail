# Aegrail MVP Tracker

Status: active
Last updated: 2026-05-12

## Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Done
- `[?]` Needs decision

## Foundation

- [x] F-001 Preserve original product idea in `idea.md`.
- [x] F-002 Create `docs`, `app`, and `data` workspace areas.
- [x] F-003 Add architecture, implementation plan, and tracker docs.
- [x] F-004 Ignore local runtime data and build output.
- [x] F-005 Create initial Go module under `app`.
- [x] F-006 Add formatting and test commands.
- [x] F-007 Add local development configuration example.
- [x] F-008 Add local Docker services area.

## Architecture Decisions

- [x] A-001 Choose modular monolith as the initial architecture.
- [x] A-002 Decide final product and binary naming: `aegrail`.
- [x] A-007 Use `pgvector/pgvector:0.8.2-pg18-trixie` for the local PostgreSQL 18 service.
- [x] A-003 Choose `goose` as the database migration tool.
- [x] A-004 Choose `pgx` with `pgxpool` for PostgreSQL access.
- [x] A-008 Prioritize WordPress and PrestaShop as first-wave target modules.
- [x] A-009 Shape Aegrail as Agent plus Hub for distributed monitoring.
- [x] A-010 Keep one repo while structuring code as Local, Hub, Agent, and Collector apps.
- [x] A-011 Add Pantheon WordPress hosting to the first-wave monitoring plan.
- [x] A-012 Add browser crawler JavaScript monitoring to the collector plan.
- [?] A-005 Decide credential encryption approach for local deployments.
- [?] A-006 Decide whether scheduled jobs live in the main binary or a worker command.

## Application Skeleton

- [x] S-001 Create `cmd/aegrail/main.go`.
- [x] S-002 Add `internal/bootstrap`.
- [x] S-003 Add `internal/domain`.
- [x] S-004 Add runtime use case packages.
- [x] S-005 Add `internal/ports` interfaces.
- [x] S-006 Add `internal/adapters/cli`.
- [x] S-007 Add `internal/adapters/http` with a chi health router.
- [x] S-008 Add zerolog initialization.
- [x] S-009 Add persistent `site add/list` CLI workflow.
- [x] S-010 Add module registry foundation.
- [x] S-011 Add `aegrail module list`.
- [x] S-012 Split internal use-case packages by runtime app.

## PostgreSQL

- [x] DB-001 Add migration runner.
- [x] DB-002 Enable `pgcrypto`, `pg_trgm`, `vector`, `btree_gin`, and `citext`.
- [x] DB-012 Add local PostgreSQL 18 Docker service with extension init script.
- [x] DB-003 Create `sites`.
- [x] DB-004 Create `evidence_imports`.
- [x] DB-005 Create `evidence_objects`.
- [x] DB-006 Create `normalized_events`.
- [x] DB-007 Create `detected_findings`.
- [x] DB-008 Create `llm_reports`.
- [x] DB-009 Add indexes for site/time/event lookup.
- [x] DB-010 Add trigram indexes for path, controller, user agent, and filenames.
- [x] DB-011 Add vector storage for compact evidence/report chunks.
- [x] DB-013 Add distributed inventory tables.
- [x] DB-014 Add deployment marker tables.
- [x] DB-015 Add Hub ingest event batch tables.
- [x] DB-016 Add distributed Hub findings table.

## Agent And Hub

- [x] AH-001 Capture Agent plus Hub architecture.
- [x] AH-002 Add distributed inventory domain types.
- [x] AH-011 Add `aegrail inventory` command group for Hub topology.
- [x] AH-012 Add top-level `aegrail hub`, `aegrail agent`, and `aegrail collector` command groups.
- [x] AH-003 Add `aegrail agent` command group.
- [x] AH-004 Add Agent local queue format under `.aegrail/queue`.
- [x] AH-005 Add Hub signed ingest API.
- [x] AH-006 Add per-agent identity and fingerprint model.
- [x] AH-007 Add event-time and received-time storage fields.
- [x] AH-008 Add cross-host app baseline comparison.
- [x] AH-009 Add deployment marker CLI import.
- [x] AH-010 Add correlation rules across host/app/service/database events.
- [x] AH-013 Implement `aegrail agent install/start/status` behavior.
- [x] AH-014 Add Hub ingest storage use case and CLI smoke path.
- [x] AH-015 Add HMAC-signed `POST /api/v1/ingest/events` endpoint.
- [x] AH-016 Add Agent enqueue/send replay to signed Hub ingest.
- [x] AH-017 Add real filesystem watcher loop for `aegrail agent start`.
- [x] AH-018 Add log tail watcher loop for web and PHP logs.
- [x] AH-019 Add inventory bootstrap helper for common single-site WordPress/PrestaShop deployments.
- [x] AH-020 Add structured Nginx, Apache, and PHP log parsers on top of tailed log events.
- [x] AH-021 Persist and list deduplicated Hub correlation findings.

## Evidence Import

- [x] I-001 Define immutable evidence manifest format.
- [x] I-002 Add SHA-256 hashing for imported files.
- [x] I-003 Implement local filesystem import.
- [x] I-004 Implement idempotent import detection.
- [x] I-005 Store raw evidence refs without placing raw data in hot tables.
- [x] I-006 Copy raw evidence into `data/evidence/{site_slug}/{import_id}`.
- [x] I-007 Add `aegrail import files`.
- [x] I-008 Add raw `aegrail import logs`.

## Normalization and Redaction

- [ ] N-001 Define canonical event Go type.
- [~] N-002 Normalize Nginx access logs.
- [~] N-003 Normalize Apache access logs.
- [~] N-004 Normalize PHP error logs.
- [x] N-005 Redact query tokens, sessions, cookies, API keys, and credentials.
- [x] N-006 Add redaction tests.

## First-Wave Modules

- [x] MOD-001 Add module registry foundation.
- [x] MOD-002 Add PrestaShop module spec.
- [x] MOD-003 Add WordPress module spec.

## PrestaShop MVP

- [x] PS-001 Add `internal/modules/prestashop`.
- [ ] PS-002 Import PrestaShop DB dump or structured export.
- [ ] PS-003 Snapshot employees.
- [ ] PS-004 Snapshot modules.
- [ ] PS-005 Snapshot configuration.
- [ ] PS-006 Snapshot tabs, hooks, and access.
- [ ] PS-007 Diff snapshots.
- [ ] PS-008 Detect new employees and SuperAdmin accounts.
- [ ] PS-009 Detect suspicious configuration values.
- [ ] PS-010 Detect suspicious module changes.

## WordPress MVP

- [x] WP-001 Add `internal/modules/wordpress`.
- [x] WP-013 Document Pantheon WordPress and Multisite monitoring plan.
- [x] WP-014 Document browser crawler monitoring for page builders and tag managers.
- [ ] WP-002 Import WordPress DB dump or structured export.
- [ ] WP-003 Snapshot users.
- [ ] WP-004 Snapshot usermeta capabilities.
- [ ] WP-005 Snapshot options.
- [ ] WP-006 Snapshot active plugins and themes.
- [ ] WP-007 Snapshot cron tasks.
- [ ] WP-008 Detect new administrators.
- [ ] WP-009 Detect changed capabilities.
- [ ] WP-010 Detect suspicious option values.
- [ ] WP-011 Detect new or changed plugins/themes.
- [ ] WP-012 Detect suspicious PHP files under writable folders.

## Secondary PHP Targets

- [ ] PHP-001 Add Mautic module spec.
- [ ] PHP-002 Add Yii2 module spec.
- [ ] PHP-003 Add Laravel module spec.
- [ ] PHP-004 Extract reusable PHP framework file/config heuristics.

## Rules and Findings

- [ ] R-001 Define rule interface and registry.
- [ ] R-002 Define versioned rule metadata.
- [x] R-003 Store deterministic findings.
- [x] R-004 Deduplicate findings across repeated runs.
- [ ] R-005 Add generic suspicious path rules.
- [ ] R-006 Add admin request anomaly rules.
- [ ] R-007 Add traffic spike rules.
- [ ] R-008 Add risk scoring.
- [ ] R-009 Add suspicious rendered JavaScript drift rules.

## Ollama and Embeddings

- [ ] LLM-001 Add Ollama client adapter.
- [ ] LLM-002 Add configurable investigation model.
- [ ] LLM-003 Add configurable embedding model.
- [ ] LLM-004 Build compact redacted evidence bundles.
- [ ] LLM-005 Store prompt template version with LLM reports.
- [ ] LLM-006 Support offline mode.
- [ ] LLM-007 Add fake LLM adapter for tests.

## Reports

- [ ] REP-001 Markdown technical report.
- [ ] REP-002 Markdown manager summary.
- [x] REP-003 JSON findings export.
- [ ] REP-004 CSV timeline export.
- [ ] REP-005 Golden tests for report rendering.

## Later

- [ ] FUT-001 chi HTTP API.
- [ ] FUT-002 Local dashboard.
- [ ] FUT-003 SSH/SFTP collector.
- [ ] FUT-004 MySQL read-only collector.
- [ ] FUT-005 Signed HTTP endpoint collector.
- [ ] FUT-006 Scheduled daily health reports.
- [ ] FUT-007 Slack, Teams, or email alerts.
- [ ] FUT-008 Pantheon provider collector for SFTP logs and DB snapshots.
- [ ] FUT-009 Pantheon WordPress Multisite network inventory and snapshot support.
- [~] FUT-010 Browser crawler collector for rendered-page JavaScript inventory.
- [ ] FUT-011 Tag-manager and third-party script allowlist/baseline support.
- [x] FUT-012 Initial browser crawler for static HTML script inventory.
- [x] FUT-013 Rendered browser crawl mode with bounded network and tag-manager waits.
- [x] FUT-014 Emit browser crawl observations into Hub event storage.
- [x] FUT-015 Browser script drift findings from Hub event history.
- [x] FUT-016 Browser script allowlist review workflow.
- [ ] FUT-017 Finding-to-allowlist handoff command.
