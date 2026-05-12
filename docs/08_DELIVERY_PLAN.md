# Delivery Plan

## Current State

Aegrail already has:

- Go module under `app`
- `aegrail` binary name
- urfave/cli command groups for Local, Hub, Agent, Collector, inventory, reports, and database migrations
- chi HTTP health and Hub ingest routing
- zerolog logging
- PostgreSQL migrations with distributed inventory and Hub ingest tables
- local PostgreSQL 18 service with pgvector
- agent install/status/enqueue/send/start workflows
- filesystem watcher profiles for WordPress and PrestaShop
- log tailing and structured Nginx, Apache, and PHP log events
- signed Hub ingest API
- Hub findings persistence and JSON export
- cross-host file baseline comparison
- event correlation findings
- browser crawler with static and rendered modes
- browser crawl ingest into Hub events
- browser script drift findings and allowlist workflow
- Pantheon WordPress monitoring plan
- dashboard and multi-site agent config plans
- multi-site Agent YAML config loading, validation, file watching, log tailing, database checks with local diff state, browser crawling, and continuous `agent run`
- deterministic Hub findings for first-wave WordPress and PrestaShop DB diff and entity events
- Hub read APIs for findings and timelines
- WordPress option, active plugin, active theme, and Multisite network option entity snapshots
- WordPress cron and script-bearing content entity snapshots
- Agent config coverage events and Hub coverage read API
- Hub inventory read APIs for apps, services, hosts, agents, and topology
- Hub deployment and browser script observation read APIs

## Phase 0: Product Foundation

Goal: make the project easy to understand and safe to extend.

Status: mostly done.

Deliverables:

- repository structure
- docs structure
- app module
- service definitions
- local development environment
- baseline migrations
- binary name decision

Exit criteria:

- new developer can understand the product, architecture, and local commands
- no sensitive runtime data is committed

## Phase 1: Hub And Agent Foundation

Goal: make distributed evidence collection real.

Status: in progress, functional for files, logs, database checks and diffs, browser crawls, queue, ingest, and multi-site agent config runs.

Deliverables:

- Hub ingest API
- agent identity
- local queue and replay
- file watcher
- log watcher
- distributed inventory
- Hub event storage
- baseline compare
- initial correlation findings

Exit criteria:

- agent can buffer events offline
- Hub can store signed event batches
- events carry distributed context
- findings can be persisted and listed
- one agent can emit site-scoped file, log, database, and browser crawl events from many configured sites

## Phase 2: Multi-Site Agent Configuration

Goal: let one server agent monitor all hosted sites from one config.

Deliverables:

- config schema `aegrail.agent.server_config.v1`
- config loader and validation
- `aegrail agent config validate`
- `aegrail agent run --config ... --once`
- per-site app/service/label event context
- per-site file and log state paths
- database collectors attached to the same config
- per-site database snapshot state and redacted diff events
- config coverage reporting to Hub

Exit criteria:

- one agent monitors `example.com`, `example2.com`, and other local site roots without state collisions
- dashboard can show which sites are covered by each agent

## Phase 3: WordPress And PrestaShop Evidence

Goal: make first-wave CMS detection strong.

Deliverables:

- WordPress database snapshot importer or collector
- PrestaShop database snapshot importer or collector
- WordPress snapshot diff rules
- PrestaShop snapshot diff rules
- suspicious option/config/module/plugin/theme/user findings
- fixture datasets for clean and suspicious states

Exit criteria:

- initial WordPress and PrestaShop DB checks emit counts, redacted digests, entity fingerprints, local diff events, and Hub findings
- WordPress admin/user capability, tracked option, cron hook, script-bearing content, active plugin, and active theme entity changes plus cron/user/option count changes produce deterministic findings
- PrestaShop employee/module entity changes plus configuration, access, hook, and tab count changes produce deterministic findings
- fixtures cover clean and suspicious cases

## Phase 4: Detection Quality And Correlation

Goal: make findings explainable, deduplicated, and useful.

Deliverables:

- rule interface and registry
- rule metadata and versions
- risk scoring
- finding status lifecycle
- finding-to-allowlist handoff
- richer multi-host incident-chain rules
- deployment-aware scoring

Exit criteria:

- every finding points to evidence
- repeated scans do not flood duplicate findings
- deployment windows influence risk without hiding suspicious changes

## Phase 5: Hub API And Dashboard

Goal: make the Hub usable for daily monitoring.

Deliverables:

- read APIs for inventory, events, findings, agents, deployments, browser scripts, and reports
- dashboard shell in TypeScript, React, and Bootstrap
- Overview, Findings, Timeline, Inventory, Sites, Agents, Browser Scripts, Deployments, Reports, and Settings views
- finding actions
- browser script allowlist actions
- auth strategy for local/pilot deployments

Exit criteria:

- dashboard reads from Hub APIs only
- operators can triage findings and inspect timelines
- agent/site coverage gaps are visible

Current API slice:

- `GET /api/v1/findings`
- `GET /api/v1/timeline`
- `GET /api/v1/coverage`
- `GET /api/v1/deployments`
- `GET /api/v1/browser/scripts`
- `GET /api/v1/inventory/apps`
- `GET /api/v1/inventory/services`
- `GET /api/v1/inventory/hosts`
- `GET /api/v1/inventory/agents`
- `GET /api/v1/inventory/topology`

## Phase 6: Reports And AI

Goal: create reliable, evidence-backed outputs.

Deliverables:

- Markdown technical report
- Markdown manager summary
- CSV timeline export
- Ollama model gateway
- redacted evidence bundle builder
- prompt templates and versions
- generated analysis storage

Exit criteria:

- reports include source finding IDs and evidence refs
- model output is labeled as analysis
- deterministic report generation works without Ollama

## Phase 7: Remote Collection And Scheduling

Goal: expand beyond local agents and manual commands.

Deliverables:

- SSH/SFTP collector
- MySQL read-only collector
- Pantheon provider collector
- scheduled browser crawls
- scheduled database snapshots
- Hub-side job queue
- notification hooks

Exit criteria:

- remote collectors are opt-in and read-only by default
- credentials are not stored or logged in plaintext
- scheduled jobs are observable and resumable

## Phase 8: Scale And Operations

Goal: make Aegrail reliable for multi-customer or larger estates.

Potential deliverables:

- per-agent secrets or mTLS
- role-based dashboard auth
- audit log
- backup and restore playbooks
- retention policies
- OpenTelemetry traces and metrics
- queue workers separated from Hub API
- object storage for larger raw evidence archives

## MVP Guardrails

Protect the core:

- multi-site agent config
- WordPress and PrestaShop evidence
- deterministic findings
- browser script drift
- Hub timelines
- dashboard triage
- reports with evidence

Everything else should serve that path.
