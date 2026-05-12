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

### Aegrail Browser Crawler Collector

Renders selected public pages in a real browser and records JavaScript evidence that is only visible after client-side execution.

Responsibilities:

- crawl a bounded set of seed URLs
- wait for page load, network quiet, and optional tag-manager settling
- inventory external scripts, inline script hashes, dynamically injected scripts, and script domains
- identify new or changed script domains compared with a baseline
- emit browser evidence events to the Hub for correlation with WordPress DB, file, log, and deployment events

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
- persist deduplicated findings for timelines, alerts, reports, and later dashboard/API reads

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

Pantheon-hosted WordPress should use the same hierarchy with provider labels. A Pantheon site environment maps naturally to an Aegrail environment, while Pantheon appserver and dbserver log sources become hosts or collector sources under that environment. WordPress Multisite should be modeled as one monitored app with logical network sites attached through labels or future child entities.

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
- comparison baseline: what the Hub has observed recently for the same app-relative path across reporting hosts

Example finding:

```text
Application file differs between production web nodes.

Expected:
web-01 and web-02 match release v1.8.2.

Observed:
web-02 has a different file hash for /var/www/app/index.php.
```

This is essential for detecting tampering on only one web node.

The Agent should send both the absolute path and, when started with `--root`, an app-relative path. The Hub should prefer the app-relative path for cross-host comparison because web nodes may mount the same application under different absolute roots.

Current comparison command:

```powershell
aegrail hub baseline compare-files --org acme --project customer-site --env production --app main-web --since 24h
```

The first comparison implementation works from recent Hub file observations. It flags app-relative paths with differing latest hashes/states across reporting hosts and paths observed on only one reporting host.

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

Current correlation command:

```powershell
aegrail hub correlate events --org acme --project customer-site --env production --app main-web --since 24h --window 30m --save
aegrail hub findings list --org acme --project customer-site --env production --app main-web
```

The first deterministic correlation rules look for:

- suspicious web activity followed by a high-signal file change
- high-signal file changes followed by sensitive database changes
- high-signal file changes followed by persistence signals such as cron or service changes
- a probable incident chain when those signals happen in sequence inside the selected window

When `--save` is used, each chain becomes a `hub_findings` row keyed by environment, rule ID, and stable correlation dedupe key. Re-running the same correlation refreshes the finding instead of duplicating it.

## Implementation Phases

1. Keep local evidence import and normalization working.
2. Add inventory tables: organizations, projects, environments, apps, services, hosts, agents.
3. Add Hub ingest storage for event batches.
4. Add Hub ingest API for signed event batches.
5. Add Agent spool format and offline queue.
6. Add deployment marker import.
7. Add single-site inventory bootstrap for WordPress and PrestaShop.
8. Add cross-host file observation comparison.
9. Add first correlation rules across hosts, apps, services, and DB events.
10. Persist and deduplicate Hub findings from deterministic correlation runs.
11. Add browser crawler collector for rendered JavaScript and tag-manager script drift.

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

The first log scan records offsets and does not replay historical lines. Later scans read appended bytes, enqueue structured log events when possible, and store redacted log text plus the original line hash. If a log is truncated or rotated, the watcher resumes from byte `0` and records the rotation in the scan result.

Current structured log parsing:

- Nginx and Apache common/combined access lines become `log.access` events with parsed method, path, redacted query, status, response bytes, user agent, source parser, and log event time.
- PHP and Apache PHP-FPM error lines become `log.php_error` events with parsed level, file, line number, source parser, Apache context when present, and log event time.
- Unrecognized lines remain redacted `log.line` events with a stable line hash, so evidence is still retained.

Initial severity remains conservative:

- PHP fatal and parse errors are `high`.
- HTTP `5xx` and generic PHP errors are `medium`.
- HTTP `4xx`, PHP warnings, notices, and deprecations are `low`.
- everything else is `info`.

## Pantheon WordPress Provider Plan

Pantheon support is planned as a provider collector for WordPress rather than a new CMS module. The first collector path should retrieve environment logs over SFTP and database state through backup download or read-only MySQL connection metadata. For Pantheon WordPress Multisite, Aegrail should snapshot network-wide tables and per-site options/capabilities while keeping the shared database model explicit in the Hub timeline.

Minimum provider events:

- `platform.log.access` or normalized `log.access` from Pantheon appserver nginx logs
- `log.php_error`, `log.php_slow`, and PHP-FPM errors from appserver logs
- `db.snapshot.created` for backup or read-only MySQL snapshot acquisition
- `db.user_changed`, `db.option_changed`, `db.plugin_changed`, and Multisite network events from WordPress snapshot diffs

Known constraint: Pantheon nginx logs do not represent every CDN-served request. Aegrail should mark those logs as appserver evidence and add CDN/Fastly log support later when complete edge visibility is required.
