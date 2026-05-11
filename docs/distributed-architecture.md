# Distributed Aegrail Architecture

Status: working draft
Date: 2026-05-12

## Goal

Aegrail should support local incident triage and centralized monitoring. The scalable shape is an Agent plus Hub architecture:

```text
Server A --\
Server B ----> Aegrail Hub -> timeline, findings, reports
Server C --/
```

The current CLI-first app remains useful for local investigations, but the data model and processing pipeline should assume that evidence can arrive from many hosts, services, apps, and environments.

## Components

Aegrail is kept in one repository, but it is developed as separate internal apps:

- `internal/hub`: central inventory, ingest, timelines, findings, reports
- `internal/agent`: per-server watcher, queue, identity, sender
- `internal/collector`: DB/app collectors for WordPress, PrestaShop, and later PHP frameworks
- `internal/local`: local/manual investigation workflows

### Aegrail Agent

Runs on monitored servers.

Responsibilities:

- watch local files, logs, config, cron, environment, and deployment markers
- collect local app evidence
- normalize obvious local events when safe
- buffer events and evidence when the Hub is unreachable
- authenticate to the Hub with a per-agent identity
- send UTC event timestamps plus local clock metadata

Agent must never lose evidence just because the network is down. Buffered data lives under a local queue such as:

```text
.aegrail/queue/
```

### Aegrail DB Collector

Runs once per database cluster or with clear ownership over specific databases.

Responsibilities:

- watch sensitive tables and settings
- record schema and migration changes
- detect role, permission, API key, webhook, payment, email, and admin table changes
- send DB events to the Hub with the same labels as host agents

### Aegrail Hub

Receives agent and collector data.

Responsibilities:

- authenticate agents
- store raw evidence refs and normalized events
- maintain host, app, service, and environment inventory
- correlate events across servers
- compare per-host and shared app baselines
- understand deployment windows
- run deterministic rules and baseline diffs
- generate timelines, findings, alerts, and reports

### Dashboard / CLI

Reads from the Hub and exports reports. The CLI should be able to work against either local storage or a Hub API.

## Inventory Hierarchy

Every event should be label-rich:

```text
Organization
  Project
    Environment
      App
        Service
          Host
            Agent
```

Required event labels:

- `org`
- `project`
- `environment`
- `app`
- `service`
- `host`
- `agent_id`
- `region`

Optional labels can include deployment ring, customer, role, PHP version, container image, or cloud instance ID.

Common single-site WordPress and PrestaShop deployments can be bootstrapped through one CLI call:

```powershell
aegrail inventory bootstrap single-site --kind wordpress --org acme --project customer-site --host web-01 --agent-id agt_web_01 --fingerprint SHA256:test
```

This creates the organization, project, `production` environment, `main-web` monitored app, `frontend` service, host, and agent identity. Larger topologies can still use the individual inventory commands so multi-node and database-owned collectors stay explicit.

## Event Timing

Store both event time and Hub receive time:

```json
{
  "event_time": "2026-05-12T19:04:30Z",
  "received_time": "2026-05-12T19:04:33Z"
}
```

All event times should be UTC. Agents should report local time sync health so timelines can mark clock drift risk.

## Baselines

Aegrail needs two baseline scopes:

- host baseline: what changed on this exact host
- shared app baseline: what should match across equivalent app nodes

Example finding:

```text
Application file differs between production web nodes.

Expected:
web-01 and web-02 match release v1.8.2.

Observed:
web-02 has a different file hash for /var/www/app/index.php.
```

This is essential for detecting tampering on only one web node.

## Deployment Awareness

Deployment markers reduce noise and improve risk scoring.

Deploy event:

```json
{
  "type": "deploy.started",
  "version": "v1.8.2",
  "commit": "a91f72c",
  "actor": "github-actions",
  "environment": "production"
}
```

File changes are less suspicious during a matching deployment window. They become more suspicious when:

- only one node changed
- the hash does not match the deployment commit
- the change happened outside a deployment window
- the change follows suspicious login or DB activity

## Security

Agent-to-Hub communication must use:

- encrypted transport
- per-agent identity
- agent tokens, mTLS, or signed requests
- event signatures
- append-only Hub event storage
- replay protection

Each agent has stable identity:

```text
agent_id: agt_web_02
host: web-02
fingerprint: SHA256:...
```

## Correlation Value

The Hub can build incident chains across servers:

```text
19:01:03  web-01     failed admin login attempts
19:02:44  web-02     successful admin login from same IP
19:04:11  web-02     new PHP file in uploads
19:04:30  db-01      admin role changed
19:05:10  worker-01  new cron job created
```

Result:

```text
Probable incident chain:
suspicious login activity -> file change on web-02 -> database privilege change -> persistence attempt on worker-01
```

## Implementation Phases

1. Keep local evidence import and normalization working.
2. Add inventory tables: organizations, projects, environments, apps, services, hosts, agents.
3. Add Hub ingest storage for event batches.
4. Add Hub ingest API for signed event batches.
5. Add Agent spool format and offline queue.
6. Add deployment marker import.
7. Add single-site inventory bootstrap for WordPress and PrestaShop.
8. Add cross-host baseline comparison.
9. Add correlation rules across hosts, apps, services, and DB events.

Current signed ingest endpoint:

```text
POST /api/v1/ingest/events
X-Aegrail-Timestamp: 2026-05-12T19:04:30Z
X-Aegrail-Signature: sha256=<hmac>
```

For the first implementation the HMAC is computed over:

```text
timestamp + "\n" + raw_request_body
```

The shared secret comes from `AEGRAIL_HUB_INGEST_SECRET`. Per-agent secrets can replace this without changing the event storage shape.

Current Agent queue:

```text
.aegrail/
  agent.json
  queue/
    pending/
    sent/
    failed/
  state/
    file-watch.json
    log-watch.json
```

`aegrail agent enqueue event` writes one JSON batch into `pending`. `aegrail agent send` signs each pending batch, posts it to the Hub ingest endpoint, and moves it to `sent` only after the Hub returns success. Failed sends stay pending so evidence is not lost.

Current filesystem watcher:

```powershell
aegrail agent start --root /var/www/site --profile wordpress
aegrail agent start --root /var/www/shop --profile prestashop --secret $env:AEGRAIL_HUB_INGEST_SECRET
```

The first scan writes a local baseline under `.aegrail/state/file-watch.json` and does not alert. Later scans enqueue `file.created`, `file.modified`, and `file.deleted` events. WordPress and PrestaShop profiles prioritize writable and high-signal paths such as uploads, plugins, themes, modules, config directories, and known sensitive config files.

The first severity rules are intentionally conservative:

- PHP-like files under upload/image paths are `high`.
- Sensitive config files are `high`.
- plugin, theme, and module changes are `medium`.
- deletes are `low` until correlation raises or lowers risk.

Current log tail watcher:

```powershell
aegrail agent start --log /var/log/nginx/access.log --log /var/log/nginx/error.log
aegrail agent start --log /var/log/php-fpm/error.log --secret $env:AEGRAIL_HUB_INGEST_SECRET
```

The first log scan records offsets and does not replay historical lines. Later scans read appended bytes, enqueue `log.line` events, and store redacted log text plus the original line hash. If a log is truncated or rotated, the watcher resumes from byte `0` and records the rotation in the scan result.

Initial log severity is intentionally simple until structured parsers land:

- PHP fatal errors, critical/emergency lines, and segmentation faults are `high`.
- HTTP `5xx`, authentication failures, permission denials, and generic errors are `medium`.
- HTTP `4xx`, warnings, and deprecations are `low`.
- everything else is `info`.
