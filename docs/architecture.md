# Aegrail Architecture

Status: working draft
Date: 2026-05-12

## Goal

Aegrail is a CLI-first security audit and incident triage system for small and medium websites, ecommerce shops, and self-hosted applications. It imports evidence, normalizes it into a shared event model, detects suspicious behavior with deterministic rules and baseline diffs, then uses a local LLM to summarize compact evidence bundles.

The first implementation should be a modular monolith in Go. This gives us simple deployment and fast iteration while preserving boundaries that can scale into background workers, an API server, agents, a central Hub, or separate services later.

For distributed monitoring details, see [Distributed Architecture](distributed-architecture.md).

## Repository Layout

```text
/
  idea.md
  app/
    go.mod
    cmd/
      aegrail/
    internal/
      bootstrap/
      domain/
      local/
      hub/
      agent/
      collector/
      ports/
      adapters/
      modules/
      rules/
      redaction/
      reports/
    migrations/
    configs/
    testdata/
  data/
  docs/
    architecture.md
    implementation-plan.md
    tracker.md
    decisions/
    brand/
  services/
    compose.yaml
    postgres18/
```

`app` contains the Go code for several Aegrail runtime apps in one module. `docs` contains product and engineering documentation. `data` is reserved for local runtime state, imported evidence, generated reports, and temporary investigation files; it is ignored by Git except for its README.

## Technology Choices

- Language: Go.
- CLI: `github.com/urfave/cli/v2`.
- HTTP API: `github.com/go-chi/chi/v5`.
- Logging: `github.com/rs/zerolog`.
- PostgreSQL driver: `github.com/jackc/pgx/v5` with `pgxpool`.
- Migrations: `github.com/pressly/goose/v3`.
- Database: PostgreSQL.
- Search and similarity: PostgreSQL full text search, `pg_trgm`, and `pgvector`.
- Local LLM: Ollama running in Docker on the local 4090 laptop GPU.

Local development services live under `services`. The first service is `postgres18`, backed by the `pgvector/pgvector:0.8.2-pg18-trixie` image and initialized with the extensions below.

PostgreSQL extensions to enable early:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS citext;
```

Optional later extensions:

- `pg_stat_statements` for database query diagnostics.
- `uuid-ossp` only if we decide not to use `gen_random_uuid()`.

## Architectural Style

Aegrail should use a ports-and-adapters modular monolith. It is one repo and one Go module, but the product is shaped as multiple internal apps:

```text
local
  local investigation workflows: init, sites, manual imports, local reports

hub
  central inventory, ingest, timeline, findings, reports, dashboard/API

agent
  per-server watcher, local queue, evidence sender, host identity

collector
  database and app-specific collectors, starting with WordPress and PrestaShop
```

```text
CLI / HTTP
  -> local / hub / agent / collector use cases
  -> domain services
  -> ports
  -> adapters
```

The domain and runtime use-case packages must not know about `chi`, `urfave/cli`, Ollama HTTP details, filesystem paths, or PostgreSQL driver types. Those concerns live in adapters.

## Core Packages

```text
internal/bootstrap
  Config loading, logger setup, DB connection, dependency wiring.

internal/domain
  Pure domain types: Site, EvidenceImport, EvidenceRef, Event, Hub ingest,
  inventory, baselines, Snapshot, Report, Severity, Confidence.

internal/local
  Local investigation use cases: init project, add site, import evidence,
  normalize evidence, scan files, diff snapshots, analyze findings, reports.

internal/hub
  Hub use cases: inventory, signed ingest, central timeline, cross-host
  correlation, shared baselines, reports.

internal/agent
  Agent runtime: local identity, filesystem/log/config watchers, offline queue,
  signed sender, local health.

internal/collector
  Collector runtime: database and app-specific state collection for WordPress,
  PrestaShop, and later Mautic/Yii2/Laravel.

internal/ports
  Interfaces for storage, collectors, parsers, redactors, rule engines,
  LLM clients, embedding clients, and clock/ID providers.

internal/adapters
  PostgreSQL repositories, filesystem evidence archive, Ollama client,
  chi HTTP handlers, urfave CLI commands, MySQL dump readers, log readers.

internal/modules
  Product-specific modules. First-wave targets: PrestaShop and WordPress.

internal/rules
  Generic rule engine, rule registry, rule metadata, rule tests.

internal/redaction
  Secret and PII minimization before storage export, embeddings, and LLM calls.

internal/reports
  Markdown, JSON, CSV, and later HTML report renderers.
```

## Runtime Pipeline

```text
collect/import
  -> create immutable evidence manifest
  -> hash files and store raw refs
  -> normalize into canonical events
  -> redact sensitive fields
  -> store normalized events and snapshots
  -> run deterministic rules
  -> compare baselines
  -> score findings
  -> build compact evidence bundle
  -> call Ollama for synthesis
  -> write reports and alerts
```

Every stage should be idempotent. Re-running an import or analysis with the same inputs should not duplicate evidence, events, or findings.

Local evidence imports copy files into:

```text
data/evidence/{site_slug}/{import_id}/
```

The database stores the source fingerprint, SHA-256 hashes, original URI, archived URI, relative path, content type, and file size. Completed imports are reused only when the archived files still exist; missing local archive files cause Aegrail to re-copy from the supplied source path.

## Canonical Domain Model

Initial entities:

- `sites`: monitored site records and safe display metadata.
- `evidence_imports`: immutable import manifests with hashes, source type, tool version, and status.
- `evidence_objects`: references to raw local files or later object storage keys.
- `normalized_events`: canonical events from logs, DB snapshots, file scans, and git diffs.
- `organizations`, `projects`, `environments`, `monitored_apps`, `services`, `hosts`, `agents`: distributed inventory for Hub deployments.
- `deployment_markers`: release windows and deployment metadata for risk scoring.
- `hub_findings`: distributed deterministic findings from Hub correlation and baseline workflows.
- `snapshots`: named point-in-time captures for DB state, file inventory, module list, user list, config list.
- `baseline_diffs`: comparison results between two snapshots.
- `detected_findings`: deterministic rule and diff findings.
- `llm_reports`: LLM-generated summaries linked to findings and evidence refs.
- `alert_deliveries`: outgoing notification attempts.

The normalized event model should include:

```text
id
site_id
import_id
occurred_at
source_type
source_ref
actor_type
actor_id
actor_email_redacted
ip
method
path
query_redacted
controller
action
status_code
bytes
user_agent
object_type
object_id
event_name
risk_tags
raw_ref
org_id
project_id
environment_id
app_id
service_id
host_id
agent_id
region
received_at
metadata_json
created_at
```

## PostgreSQL Strategy

Use PostgreSQL from the start to avoid a later storage migration.

Recommended patterns:

- Use UUID primary keys generated by `gen_random_uuid()`.
- Store raw evidence outside hot tables; store hashes and refs in PostgreSQL.
- Partition `normalized_events` by time once volume requires it.
- Index by `site_id`, `occurred_at`, `source_type`, `event_name`, and selected JSONB expressions.
- Use GIN indexes for JSONB risk tags and metadata lookup.
- Use `pg_trgm` indexes for suspicious path, controller, module, user agent, and filename searches.
- Use `vector` only for compact evidence bundles, report chunks, and investigation notes, not raw logs.

Initial job orchestration can use a PostgreSQL-backed jobs table with `FOR UPDATE SKIP LOCKED`. That keeps deployment simple while allowing later worker separation.

## Ollama Strategy

Ollama must be an adapter behind these ports:

```text
LLMClient.GenerateInvestigation(ctx, bundle) -> InvestigationDraft
EmbeddingClient.EmbedTexts(ctx, texts) -> []Embedding
```

Suggested local model roles:

- Investigation synthesis: `qwen3:30b` as a strong default for the 4090 laptop if available.
- Faster local investigation: `qwen3:8b`.
- Heavier quality option: `llama3.3:70b` when the local runtime can handle it.
- Embeddings: `qwen3-embedding` or `bge-m3`.

The model name, Ollama base URL, context limits, timeout, and offline mode must be configuration, not hard-coded.

Never send raw unredacted logs, database dumps, cookies, credentials, payment data, or customer records to the LLM. The LLM receives only compact, redacted evidence bundles with deterministic finding IDs and evidence refs.

## Module System

Modules provide source-specific logic without leaking into core packages.

First-wave modules:

```text
internal/modules/prestashop
  collectors/
  snapshots/
  normalizers/
  rules/
  reports/

internal/modules/wordpress
  collectors/
  snapshots/
  normalizers/
  rules/
  reports/
```

A module can register:

- Source importers.
- Snapshot builders.
- Normalizers.
- Rules.
- Report fragments.
- Suggested next checks.

The core rule engine should treat module rules and generic rules the same way.

Target priority:

- Wave 1: PrestaShop and WordPress/WooCommerce.
- Wave 2: Mautic, Yii2 applications, and Laravel applications.

Wave 1 must be strong from the beginning. These modules should get dedicated snapshot models, diff categories, and rule packs instead of relying only on generic PHP/log heuristics.

## Security Model

Required from the first implementation:

- Read-only collection by default.
- Immutable evidence manifests.
- SHA-256 hashes for imported files and generated snapshots.
- Redaction before LLM, embeddings, exports, and manager reports.
- Configurable local-only mode.
- No credentials in logs.
- Encrypted credential storage before any live remote collectors are shipped.
- Report every tool version, rule version, model name, and prompt template version.

## Observability

Use `zerolog` for structured logs. Every log event should carry useful identifiers:

- `site_id`
- `import_id`
- `job_id`
- `rule_id`
- `finding_id`
- `source_type`

CLI output should be human-readable. Logs should be machine-readable. Avoid mixing report content with diagnostic logs.

## API and CLI Relationship

The CLI is first, but it should call the same runtime use-case packages that HTTP handlers call later.

Examples:

```text
aegrail init
aegrail db migrate
aegrail db status
aegrail hub serve
aegrail hub ingest event
aegrail hub ingest batch list
aegrail hub baseline compare-files
aegrail hub correlate events --save
aegrail hub findings list
aegrail agent install
aegrail agent start
aegrail agent start --log /var/log/nginx/access.log
aegrail agent enqueue event
aegrail agent send
aegrail agent status
aegrail collector db start
aegrail site add
aegrail site list
aegrail inventory org add
aegrail inventory bootstrap single-site
aegrail inventory project add
aegrail inventory env add
aegrail inventory app add
aegrail inventory host add
aegrail inventory agent register
aegrail inventory deploy add
aegrail import logs
aegrail import prestashop-db
aegrail diff db
aegrail scan files
aegrail analyze
aegrail report
aegrail serve
```

The future `aegrail serve` command should start a chi API using the same configured application container.

## Testing Strategy

Use tests at the boundaries where mistakes are expensive:

- Golden tests for log parsing and report rendering.
- Table-driven tests for rules.
- Integration tests for PostgreSQL repositories with migrations.
- Redaction tests with known secret patterns.
- Snapshot diff tests with small PrestaShop and WordPress fixtures.
- LLM adapter contract tests using recorded or fake responses.

The LLM must not be needed for deterministic unit tests.
