# Aegrail Implementation Plan

Status: working draft
Date: 2026-05-12

## Phase 0: Repository Foundation

Goal: make the project easy to understand and safe to extend.

Deliverables:

- `docs` architecture, plan, tracker, and decisions.
- `app` Go application home with documented package layout.
- `data` runtime area documented and ignored by Git.
- Initial `.gitignore` for runtime data, env files, and build output.
- `services` local Docker services area with PostgreSQL 18.

Exit criteria:

- A new contributor can understand where code, docs, and local data belong.
- Sensitive imported evidence will not be accidentally committed.

## Phase 1: Go Application Skeleton

Goal: create a compiling CLI-first modular monolith.

Deliverables:

- `app/go.mod`.
- `cmd/aegrail/main.go`.
- `internal/bootstrap` for config, logger, database wiring.
- `internal/adapters/cli` with `init`, `hub`, `agent`, `collector`, `site`, `import`, `analyze`, and `report` command groups.
- `internal/adapters/http` with an initial chi router and health endpoint.
- `internal/adapters/postgres` with pgx repositories and goose migrations.
- `internal/domain` with initial entity types.
- `internal/local`, `internal/hub`, `internal/agent`, and `internal/collector` runtime use case packages.
- Basic config file format and env overrides.

Exit criteria:

- `go test ./...` passes.
- `go run ./cmd/aegrail --help` works.
- Logging uses zerolog.
- `aegrail serve` exposes `/healthz`.
- `aegrail site add/list` persists through PostgreSQL after migrations.

## Phase 2: PostgreSQL Foundation

Goal: create durable storage for sites, evidence imports, events, findings, and reports.

Deliverables:

- Migration runner.
- Migration status command.
- PostgreSQL extensions: `pgcrypto`, `pg_trgm`, `vector`, `btree_gin`, `citext`.
- Tables for `sites`, `evidence_imports`, `evidence_objects`, `normalized_events`, `detected_findings`, and `llm_reports`.
- Repository interfaces in `internal/ports`.
- PostgreSQL adapters in `internal/adapters/postgres`.

Exit criteria:

- Migrations can be applied to an empty database.
- CLI can create and list sites.
- A smoke test verifies insert/read for site and evidence import records.
- `aegrail db migrate`, `aegrail db status`, `aegrail site add`, and `aegrail site list` work against local PostgreSQL.

## Phase 3: Evidence Import and Normalization

Goal: import local evidence safely and normalize the first source types.

Deliverables:

- Filesystem evidence archive adapter.
- Immutable evidence manifest with SHA-256 hashes.
- Nginx and Apache access log import.
- PHP error log import.
- Canonical event model.
- Redaction package for query strings, tokens, cookies, credentials, and common PII.

Exit criteria:

- `aegrail import logs --site ... --path ...` stores evidence refs and normalized events.
- Re-running the same import is idempotent.
- Redaction tests pass on representative risky inputs.

Current status:

- Raw local file and log evidence import is implemented.
- Raw evidence is copied into `data/evidence/{site_slug}/{import_id}`.
- Agent-tailed Nginx, Apache, and PHP logs now produce structured Hub events. Local evidence-import normalization still needs the same parser path before `N-002` to `N-004` can be called complete.

## Phase 4: WordPress And PrestaShop MVP Modules

Goal: detect concrete high-value WordPress/WooCommerce and PrestaShop security signals.

Deliverables:

- PrestaShop module package.
- WordPress module package.
- SQL dump or CSV snapshot importer for initial MVP.
- Pantheon WordPress monitoring plan for access logs and database snapshots.
- Browser crawler monitoring plan for rendered JavaScript and tag-manager-loaded scripts.
- PrestaShop snapshot builders for employees, sessions, logs, modules, configuration, tabs, hooks, and access.
- WordPress snapshot builders for users, usermeta capabilities, options, active plugins, themes, cron, posts/pages with scripts, and file inventory.
- Baseline diff engine for two snapshots.
- Initial PrestaShop finding types:
  - new employee account
  - new SuperAdmin account
  - employee profile or password timestamp change
  - suspicious configuration value
  - new or changed module
  - suspicious admin controller or tab
- Initial WordPress finding types:
  - new administrator account
  - changed user capabilities
  - suspicious option value
  - new or changed plugin/theme
  - unexpected `wp-cron` task
- suspicious JavaScript in posts, widgets, or options
- new or changed rendered JavaScript domains and inline script hashes
- PHP files added under writable folders

Exit criteria:

- `aegrail import prestashop-db` creates a snapshot.
- `aegrail import wordpress-db` creates a snapshot.
- `aegrail diff db --from ... --to ...` produces deterministic findings.
- Fixtures cover clean and suspicious PrestaShop and WordPress diffs.
- Pantheon-hosted WordPress single installs and Multisite networks have a documented collector path for access logs and DB snapshots.
- Rendered-page JavaScript monitoring has a documented collector path, including bounded waits for tag managers and dynamic page-builder scripts.

Current Pantheon direction:

- Treat Pantheon as a hosting provider adapter around WordPress, not as a separate CMS module.
- Minimum viable collection is SFTP application/database logs plus backup-based or read-only MySQL database snapshots.
- WordPress Multisite networks are represented as one monitored app with logical network sites under it.
- See [Pantheon WordPress Monitoring Plan](platforms/pantheon-wordpress.md).

Current browser crawler direction:

- Treat browser crawling as a generic collector with WordPress-aware presets.
- `aegrail collector browser crawl` can fetch supplied URLs, parse initial HTML, inventory scripts, redact script URLs, hash inline scripts, and detect obvious tag-manager IDs.
- `--rendered` uses an installed Chrome/Chromium browser so dynamic scripts injected by page builders, widgets, consent tools, and tag managers are visible.
- Rendered mode waits for browser readiness, network quiet, optional tag-manager settling, and a bounded extra settle delay.
- `--ingest` saves browser crawl observations into Hub ingest events for timelines, correlation, and later findings.
- `aegrail hub correlate browser-scripts --save` compares observed script domains, inline hashes, and tag-manager IDs against per-page Hub event baselines.
- `aegrail hub browser-scripts allow` records reviewed script domains, inline hashes, or tag-manager IDs so known-good values stop recurring as drift findings.
- See [Browser Crawler And JavaScript Monitoring Plan](collectors/browser-crawler.md).

## Phase 4B: Secondary PHP Targets

Goal: add support for Mautic, Yii2, and Laravel after the first-wave ecommerce/CMS modules are reliable.

Deliverables:

- Mautic module package.
- Yii2 module package.
- Laravel module package.
- Shared PHP framework file/config/session heuristics where they are genuinely reusable.
- Module-specific rule packs for framework conventions.

Exit criteria:

- Secondary modules reuse the same module registry, snapshot, diff, and rule interfaces.
- Generic PHP rules do not dilute WordPress and PrestaShop-specific detections.

## Phase 5: Rule Engine and Risk Scoring

Goal: make detections explainable, versioned, and testable.

Deliverables:

- Rule registry.
- Rule metadata: ID, name, version, severity, confidence, tags.
- Rule result model with evidence refs and recommended next checks.
- Hub findings persistence for deterministic correlation chains.
- Generic rules for suspicious paths, admin requests, login anomalies, webshell filenames, and traffic spikes.
- Risk scoring service that combines rule severity, confidence, and evidence count.

Exit criteria:

- Rules can be run by site and time window.
- Findings are deduplicated across repeated runs.
- Rule output is stable enough for golden tests.

Current status:

- Hub correlation chains can be saved into `hub_findings` with a stable dedupe key.
- `aegrail hub findings list` can inspect persisted distributed findings.
- `aegrail report hub-findings` exports persisted Hub findings as JSON.

## Phase 6: Ollama Investigation Layer

Goal: generate readable synthesis without weakening deterministic evidence handling.

Deliverables:

- Ollama client adapter.
- Model configuration:
  - investigation model
  - embedding model
  - base URL
  - timeout
  - context budget
  - offline mode
- Evidence bundle builder.
- Prompt templates with version IDs.
- LLM report storage with source finding refs.

Exit criteria:

- `aegrail analyze --site ... --since ...` can run with Ollama when enabled.
- Offline mode skips LLM calls cleanly.
- LLM output is labeled as analysis and references deterministic finding IDs.

## Phase 7: Reports

Goal: produce useful artifacts for technical and non-technical users.

Deliverables:

- Markdown technical report.
- Markdown manager summary.
- JSON findings export.
- CSV timeline export.
- Report renderer tests.

Exit criteria:

- `aegrail report hub-findings --org ... --project ... --env ...` writes JSON findings to stdout or `--output`.
- `aegrail report --site ... --format md` writes a report.
- Report includes tool version, rule versions, model name, prompt version, and evidence refs.
- Reports do not include unredacted secrets.

## Phase 8: HTTP API and Dashboard Preparation

Goal: prepare for a web dashboard without changing core logic.

Deliverables:

- `aegrail serve`.
- chi router.
- Health endpoint.
- Site, import, finding, report read endpoints.
- Basic auth strategy decision.

Exit criteria:

- API reads from the same runtime use-case packages as CLI.
- No duplicate business logic in handlers.

## Phase 9: Agent And Hub Foundation

Goal: support distributed monitoring without weakening local evidence workflows.

Deliverables:

- Inventory schema for organizations, projects, environments, apps, services, hosts, and agents.
- Agent identity model.
- Hub ingest API for signed event batches.
- Agent spool format under `.aegrail/queue`.
- UTC event time and Hub received time.
- Deployment marker import.
- Cross-host app baseline model.

Exit criteria:

- A local agent can buffer events offline and replay them to a Hub.
- Hub can group events by org/project/environment/app/service/host.
- Hub can distinguish event time from received time.
- Deployment windows influence file-change risk scoring.

Current status:

- Distributed inventory tables and Hub use cases exist.
- `aegrail inventory` can create organizations, projects, environments, apps, services, hosts, agent identities, and deployment markers.
- `normalized_events` now has distributed context columns plus Hub `received_at` storage.
- Internal packages are split by runtime app: `local`, `hub`, `agent`, and `collector`.
- Hub ingest batch/event storage exists with a CLI smoke path.
- `aegrail hub serve` exposes HMAC-signed `POST /api/v1/ingest/events`.
- `aegrail agent install`, `agent enqueue event`, `agent status`, and `agent send` support offline queue/replay.
- `aegrail agent start` can baseline and poll filesystem paths, including WordPress and PrestaShop watch profiles, then queue and optionally replay signed events.
- `aegrail agent start --log` can baseline and tail web/PHP log files or directories, enqueue redacted structured log events, and optionally replay signed events.
- `aegrail collector browser crawl --ingest ...` stores static/rendered page and script observations as Hub events.
- `aegrail inventory bootstrap single-site` creates the first common WordPress or PrestaShop Hub topology in one idempotent step.
- Tailed Nginx/Apache access logs and PHP error logs now produce structured `log.access` and `log.php_error` events while retaining redacted raw line evidence.
- `aegrail hub baseline compare-files` compares recent app-relative file observations across reporting hosts.
- `aegrail hub correlate events --save` runs the first deterministic incident-chain rules and persists deduplicated Hub findings.
- `aegrail hub correlate browser-scripts --save` persists browser JavaScript drift findings from Hub event history.
- `aegrail hub browser-scripts allow` and `allowlist` support reviewed browser script drift approvals.
- Per-agent secrets, richer topology templates, persisted baseline snapshots, and report/export reads from Hub findings remain the next Hub priorities.

## Phase 10: Remote Collection and Scheduling

Goal: move beyond manual imports once the local workflow is stable.

Deliverables:

- SSH/SFTP collector.
- MySQL read-only collector.
- Pantheon provider collector using SFTP logs and Terminus or dashboard-derived connection metadata.
- Browser crawler collector for rendered-page JavaScript inventory and drift detection.
- Signed HTTP endpoint collector.
- PostgreSQL-backed job queue.
- Scheduling model for daily health reports.
- Encrypted credential storage.

Exit criteria:

- Remote collectors are opt-in and read-only by default.
- Credentials are not logged or stored in plaintext.
- Collection jobs are resumable and observable.
