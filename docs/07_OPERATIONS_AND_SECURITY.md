# Operations And Security

## Environments

Recommended environments:

- local developer
- lab/demo
- staging
- production pilot
- production

Each environment should have separate:

- config
- database
- Hub ingest secret
- agent identities
- model endpoint
- dashboard auth
- logs and metrics
- backups

## Configuration

Configuration should be explicit and versioned:

- Hub URL
- agent identity
- monitored sites
- watched paths
- log paths
- database DSN environment variable names
- browser crawl URLs
- collection intervals
- model sets
- feature flags
- redaction policy

Runtime admin changes such as allowlists and finding state should be stored in the database and exportable later.

Detailed multi-site config plan: [Agent Multi-Site Configuration](configuration/agent-multi-site.md).

## Agent And Hub Security

Before production use:

- require signed ingest requests
- use TLS between agents and Hub
- support per-agent secrets or mTLS
- identify every agent by host, ID, and fingerprint
- reject stale request timestamps
- keep event batches append-only after ingest
- store local queue files with restrictive permissions
- avoid logging secrets

## Dashboard Security

The dashboard must not be public without authentication.

First local version:

- reverse proxy or single admin auth
- secure cookies
- no unauthenticated debug endpoints

Later:

- users and roles
- analyst read-only role
- admin role for allowlists and settings
- action audit log
- session expiration

## Database Security

Collector credentials should be read-only where possible.

Rules:

- never commit DSNs with passwords
- prefer `dsn_env` or secret file references
- limit collector permissions to required tables
- do not log raw query results
- redact sensitive DB values before reports and prompts

## Time Sync

Incident timelines require accurate time.

Agents and Hub should:

- use UTC for stored events
- record event time and Hub received time
- report clock skew hints
- recommend NTP or equivalent time sync

## Queue And Jobs

The local agent queue is durable and filesystem-backed.

Redis or NATS may be useful later for Hub-side jobs:

- scheduled browser crawls
- report generation
- database snapshot jobs
- model analysis jobs
- notification jobs

Do not require Redis for the first agent-to-Hub evidence path. PostgreSQL remains the source of truth.

## Observability

Track:

- agent last seen
- pending/sent/failed queue batches
- events ingested by org/project/environment/app
- event rejection count
- file scan counts
- log line counts
- browser crawl counts and failures
- database snapshot counts and failures
- finding counts by severity and rule
- correlation job latency
- model latency and error rate
- dashboard API latency

## Backups

PostgreSQL is the source of truth for Hub state.

Back up:

- schema
- inventory
- events
- findings
- snapshots
- allowlists
- reports
- prompt/model metadata
- redacted evidence bundle hashes
- model analysis report hashes and statuses

Raw local evidence on agents may need separate host-level backup or retention policy depending on customer requirements.

## Failure Modes

Aegrail should degrade gracefully:

- if Hub is unreachable, agents keep queueing locally
- if Ollama is down, deterministic findings and reports still work
- if `AEGRAIL_OLLAMA_OFFLINE=true`, model calls are disabled while deterministic collection, rules, and reports continue
- if a model report cannot be completed, the exported report should record `offline` or `failed` status with bundle and prompt provenance
- if evidence bundles are exported for model use, they must stay compact and redacted before leaving the deterministic pipeline
- if browser crawling fails, file/log/database monitoring continues
- if one site config is invalid, validation should identify the site clearly
- if a database snapshot fails, other configured sites continue
- if dashboard is unavailable, CLI workflows still work

## Release Discipline

Every release should include:

- migration review
- config schema review
- redaction test run
- rule fixture test run
- dashboard smoke test
- agent queue replay smoke test
- rollback notes
