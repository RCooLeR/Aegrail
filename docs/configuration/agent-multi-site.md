# Aegrail Agent Multi-Site Configuration

Status: in progress; validation plus file/log/database/browser multi-site runs implemented
Date: 2026-05-12

Canonical context:

- [Domain Model](../03_DOMAIN_MODEL.md)
- [Evidence Collection](../04_EVIDENCE_COLLECTION.md)
- [Operations And Security](../07_OPERATIONS_AND_SECURITY.md)
- [Delivery Plan](../08_DELIVERY_PLAN.md)

This document defines the target operator-facing configuration for running one Aegrail Agent on a server that hosts multiple sites or applications.

The goal is simple:

```text
one server
  one Aegrail Agent process
  one host identity
  many monitored sites
  one central Hub timeline
```

## Why This Matters

Shared hosting, agency servers, managed VPS boxes, and multi-site production nodes often host several unrelated applications:

```text
web-01
  /var/www/example.com/
  /var/www/example2.com/
  /var/www/shop.example.net/
```

If the agent only has one global `app` and `service`, the Hub cannot cleanly separate findings for each site. Aegrail must keep host identity and site context separate.

## Current Command

Validate the config:

```powershell
aegrail agent config validate --config /etc/aegrail/agent.yaml
```

Run the agent from the config:

```powershell
aegrail agent run --config /etc/aegrail/agent.yaml
```

For local development:

```powershell
cd app
go run ./cmd/aegrail agent config validate --config configs/agent.multi-site.yaml.example
go run ./cmd/aegrail agent run --config configs/agent.multi-site.yaml.example
```

The current implementation uses the config for file watching, log tailing, database snapshot checks, browser crawls, queueing, replay, and per-site app/service labels.

## Configuration Shape

The config has three layers:

- `hub`: where evidence goes and how the agent authenticates.
- `identity`: host-level identity shared by every event from this agent.
- `sites`: per-site collection rules, labels, database DSNs, crawl URLs, and state.

Secrets should be referenced by environment variable name or file path, not embedded as plaintext.

## Example

See [`app/configs/agent.multi-site.yaml.example`](../../app/configs/agent.multi-site.yaml.example).

Reduced example:

```yaml
schema: aegrail.agent.server_config.v1

hub:
  url: http://127.0.0.1:8787
  ingest_secret_env: AEGRAIL_HUB_INGEST_SECRET

identity:
  org: acme
  project: hosted-sites
  environment: production
  host: web-01
  agent_id: agt_web_01
  region: eu-central

runtime:
  queue_dir: /var/lib/aegrail/queue
  state_dir: /var/lib/aegrail/state
  interval: 30s

sites:
  - slug: example-com
    domain: example.com
    app: example-com
    service: frontend
    kind: wordpress
    root: /var/www/example.com
    files:
      profiles: [wordpress]
    logs:
      - path: /var/log/nginx/example.com.access.log
        kind: nginx_access
    databases:
      - name: wordpress
        engine: mysql
        dsn_env: AEGRAIL_DB_EXAMPLE_COM_DSN
        profile: wordpress
        table_prefix: wp_
        timeout: 10s
    browser_crawl:
      enabled: true
      rendered: true
      wait_tag_manager: true
      urls:
        - https://example.com/
```

## Site Context Rules

Each event emitted for a configured site should carry:

- `org`
- `project`
- `environment`
- `app`
- `service`
- `host`
- `agent_id`
- `region`
- `labels`

Host-level values come from `identity`. Site-level values override only `app`, `service`, and labels. This lets one server produce clean Hub timelines for many sites.

Example event context:

```json
{
  "org": "acme",
  "project": "hosted-sites",
  "environment": "production",
  "app": "example-com",
  "service": "frontend",
  "host": "web-01",
  "agent_id": "agt_web_01",
  "type": "file.created",
  "target": "/var/www/example.com/wp-content/uploads/avatar.php",
  "severity": "high"
}
```

## State Layout

One global file baseline will not work for multiple sites. Each site needs isolated state.

Target layout:

```text
/var/lib/aegrail/state/
  sites/
    example-com/
      file-watch.json
      log-tail.json
      browser-crawl.json
      db-wordpress.json
    example2-com/
      file-watch.json
      log-tail.json
      browser-crawl.json
      db-prestashop.json
```

This prevents a scan of `example2.com` from overwriting the baseline for `example.com`.

## Files

Each site can use a built-in profile and optional additional paths:

```yaml
files:
  profiles: [wordpress]
  extra_paths:
    - /var/www/example.com/mu-plugins
  exclude:
    - /var/www/example.com/wp-content/cache
```

Initial profiles:

- `wordpress`
- `prestashop`

Future profiles:

- `mautic`
- `yii2`
- `laravel`
- `generic-php`

## Logs

Logs are attached to the site they belong to:

```yaml
logs:
  - path: /var/log/nginx/example.com.access.log
    kind: nginx_access
  - path: /var/www/example.com/wp-content/debug.log
    kind: php_error
```

Directory paths should be allowed when a host rotates logs into per-site directories.

## Databases

Database access is per site and should be read-only when possible.

```yaml
databases:
  - name: wordpress
    engine: mysql
    dsn_env: AEGRAIL_DB_EXAMPLE_COM_DSN
    profile: wordpress
    table_prefix: wp_
    timeout: 10s
    schedule: 15m
```

Current implementation:

- `aegrail agent run --config ...` runs configured database checks on every scan.
- MySQL and MariaDB are supported first because WordPress and PrestaShop are first-wave targets.
- PostgreSQL can be represented in config, but collector support is still planned.
- DSNs must come from `dsn_env`; literal DSNs in config are rejected.
- If `dsn_env` is missing at runtime, the agent queues `db.coverage.warning` instead of failing the whole scan.
- Events are emitted under `source=agent.database` and `service=database`.
- Sensitive DB values are not queued raw. Aegrail records counts, value byte lengths, and SHA-256 digests for selected option/config values.
- The first successful snapshot creates a per-site, per-database JSON baseline in `runtime.state_dir`.
- Later snapshots compare against that state and emit `db.snapshot.check_changed` or `db.snapshot.check_added` events when counts or digests change.
- Failed or warning-only snapshots do not overwrite the previous good DB state.
- `schedule` is accepted as config metadata; independent per-database scheduling is still planned. The current runner executes DB checks on the agent scan interval.

Minimum WordPress database checks:

- users and administrator roles
- usermeta capabilities
- options
- active plugins and themes
- cron tasks
- suspicious script-bearing posts, pages, widgets, and builder content

Implemented WordPress check events:

- `wordpress.users.count`
- `wordpress.admin_users.count`
- `wordpress.options.count`
- `wordpress.active_plugins.digest`
- `wordpress.cron.digest`
- `wordpress.theme_stylesheet.digest`
- `wordpress.theme_template.digest`

Minimum PrestaShop database checks:

- employees and SuperAdmin status
- sessions and recent logins
- configuration values
- modules
- tabs, hooks, and access rules

Implemented PrestaShop check events:

- `prestashop.employees.count`
- `prestashop.active_employees.count`
- `prestashop.modules.count`
- `prestashop.active_modules.count`
- `prestashop.configuration.count`
- `prestashop.hooks.count`
- `prestashop.tabs.count`
- `prestashop.access_rules.count`

## Browser Crawling

Browser crawler settings belong per site:

```yaml
browser_crawl:
  enabled: true
  rendered: true
  wait_tag_manager: true
  max_pages: 8
  urls:
    - https://example.com/
    - https://example.com/contact/
```

Rendered crawling should use bounded waits, not unbounded browser sessions. Aegrail should wait for tag-manager-loaded scripts when configured, then settle for a short maximum duration.

## WordPress Multisite

WordPress Multisite should be represented as one `site` with optional logical network sites:

```yaml
sites:
  - slug: network-main
    domain: example.com
    kind: wordpress-multisite
    root: /var/www/example.com
    wordpress:
      multisite: true
      network_sites:
        - blog_id: 1
          domain: example.com
        - blog_id: 2
          domain: shop.example.com
```

The Hub should group the network as one app while still allowing findings to reference a specific `blog_id` or domain.

## Validation Rules

The `agent config validate` command checks:

- required `hub`, `identity`, and `sites` fields
- unique site slugs
- absolute local paths for roots, logs, queue, and state
- valid URL values for Hub and browser crawl seeds
- known site kinds and profiles
- no literal database passwords in committed example configs
- safe database table prefixes
- valid durations for runtime interval, database timeout/schedule, and browser timeout

Future live validation should also check:

- DSN environment variables exist on the target server
- no duplicate path ownership between unrelated site configs unless explicitly allowed

## Hub Inventory Sync

The agent should optionally report its config coverage to the Hub:

```text
web-01
  agent agt_web_01
    monitors example-com
      files: wordpress profile
      logs: nginx access, PHP debug
      db: wordpress
      browser: rendered crawl
    monitors example2-com
      files: prestashop profile
      logs: nginx access, PHP error
      db: prestashop
```

The dashboard can then show which sites are covered, partially covered, or not covered.

## Implementation Steps

Done:

1. Add a config loader for `aegrail.agent.server_config.v1`.
2. Add per-site app/service/label overrides to queued events.
3. Add per-site file and log state paths.
4. Add `aegrail agent config validate`.
5. Add `aegrail agent run --config ... --once`.
6. Extend `agent run` to continuously scan every configured site and replay queued batches.
7. Run browser crawls from configured `browser_crawl`.
8. Run database collectors from configured `databases`.
9. Persist DB snapshot state and emit redacted DB diff events.
10. Turn first-wave DB diff events into deterministic Hub findings.

Next:

1. Report config coverage to the Hub for dashboard views.
2. Add entity-level DB snapshots so findings can name the exact user, plugin, module, or option that changed.
