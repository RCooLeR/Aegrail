# Agent How It Works

This document explains what the Agent actually does under the hood: schedules, collectors, SQL queries, transformations, queue files, encryption, and Hub ingest.

## Evidence Collection

Agents collect evidence from configured sites:

- File scans: created, modified, deleted files. The agent sends path, relative path when possible, size, modification time, SHA-256 when hashed, and previous metadata for diffs. It does not send file contents.
- Logs: access logs and PHP errors. The agent sends normalized request/error events with secret-bearing query values, cookies, authorization-like strings, tokens, and passwords redacted. Access log remotes are checked against a cached Tor exit list when Tor checking is enabled.
- Databases: read-only WordPress, PrestaShop, Mautic, Yii2 RBAC, and Laravel snapshots. The agent sends counts, hashes/digests of selected option/config values, and entity observations such as users, employees, plugins, themes, modules, roles, permissions, RBAC assignments, integrations, webhooks, OAuth clients, cron entries, content-script indicators, and selected configuration keys.
- Browser crawls: rendered or non-rendered page observations. The agent sends redacted page/final URLs, redacted script URL variants, script domains/paths, inline script hashes/byte sizes, tag manager IDs, site icon candidates, crawl warnings, and the crawler User-Agent that was used.
- Coverage: what collectors are enabled for each site and whether expected local collectors are intentionally disabled.

Database account evidence:

- WordPress users, PrestaShop employees, Mautic users, Yii2 RBAC users, and Laravel users may include the normalized full email/login in event payloads so findings can identify which account changed.
- Masked account hints such as `r***n@example.com` are also stored for display.
- When `AEGRAIL_PII_KEY` is set, the agent also adds stable HMAC-SHA256 fingerprints for account identifiers. These are one-way fingerprints, not reversible encryption.
- Database DSNs are read from `dsn_env`; literal DSNs with credentials are rejected by config validation.
- Raw WordPress option values, PrestaShop configuration values, Mautic integration secrets, OAuth secrets, and webhook secrets are not emitted. The collector sends counts, SHA-256 digests, byte sizes, selected safe keys, and change signatures.

## Scheduler

From `agent/`, `go run ./cmd/agent run --config <file>` loads the YAML config, normalizes defaults, and repeats `runOnce` every `runtime.interval`. The default interval is `30s` when the config does not set one.

Each pass does this:

1. File/log scan with `RunServerConfigOnce`.
2. Database collectors for each configured `sites[].databases[]`.
3. Browser crawls for each enabled `sites[].browser_crawl`.
4. Config coverage event, unless the pass is `--bootstrap`.
5. Queue events locally.
6. Encrypt pending batches as wire envelopes and send them to Hub.

Collector-specific schedules sit inside that loop:

- `sites[].databases[].schedule`: if set, the database collector skips until the state file is older than that duration.
- `sites[].browser_crawl.schedule`: same idea for browser crawls.
- Config coverage queues only when the config coverage signature changes or the heartbeat is due. Default heartbeat is `10m`; override with `AEGRAIL_CONFIG_COVERAGE_HEARTBEAT_INTERVAL`.
- File scans run each loop, but unchanged files are cheap: the agent reuses the previous SHA-256 when path, size, mtime, and status-change time are unchanged. A forced full hash refresh happens every `1h` by default; override with `AEGRAIL_WATCH_FULL_HASH_INTERVAL`.

## File Collector

For each site with file monitoring enabled, the agent builds a path list from the site profile (`wordpress`, `prestashop`, `mautic`, `yii2-rbac`, `laravel`, etc.), `files.extra_paths`, and `files.exclude`.

It ignores obvious noise:

- `.git`
- `.aegrail`
- the configured queue/state directories
- cache/temp/tmp-style directories
- common generated media under writable asset paths like `uploads`, `upload`, and `img`
- low-signal binary assets under package/code trees such as plugin/theme images, fonts, maps, audio/video, and PDFs
- Mautic runtime/cache/log/session/spool/temp directories

The file scanner intentionally does not trust a parent directory timestamp as proof that the whole subtree is unchanged. On normal filesystems, editing an existing PHP file changes the file metadata, not necessarily the parent directory metadata. A pure "directory hash" shortcut would be fast, but it could miss timestomped or same-name file edits. Aegrail instead keeps a local state index, checks cheap file metadata every pass, reuses content hashes when metadata is unchanged, and periodically forces content rehashing.

Built-in profile paths:

- `wordpress`: `wp-config.php`, `wp-config-local.php`, `wp-content/uploads`, `wp-content/plugins`, `wp-content/themes`.
- `prestashop`: `app/config`, `config`, `img`, `modules`, `themes`, `upload`, `var/logs`.
- `mautic`: `.env`, `app/config`, `config`, `media`, `plugins`, `themes`.
- `yii2-rbac`: `composer.json`, `composer.lock`, `yii`, `requirements.php`, `firewall.php`, `config`, `components`, `controllers`, `helpers`, `models`, `migrations`, `traits`, `widgets`, `mail`, `mailer`, `views`, `commands`, and selected `web/*.php` entrypoints.
- `laravel`: `.env`, `artisan`, Composer/npm lockfiles, Vite/Tailwind/PostCSS config, `app`, `bootstrap/app.php`, `bootstrap/providers.php`, `config`, `database/migrations`, `database/seeders`, `resources/views`, `resources/js`, `resources/css`, `routes`, and selected `public` entrypoints.

Mautic file severity rules:

- `app/config/parameters.php`, `app/config/local.php`, `app/config/config.php`, and `.env` are high risk.
- PHP/PHAR/PHTML in `media` is high risk.
- Plugin/theme code changes are medium by default.
- Static media/tracking assets are ignored unless they are executable or otherwise high signal.

Yii2 RBAC file severity rules:

- `config/db.php`, `config/web.php`, `config/web_prod.php`, `config/console.php`, and `config/console_prod.php` are high risk because they can change database access, app wiring, and production behavior.
- PHP/PHAR/PHTML in writable web/runtime/asset-style paths is high risk.
- Source changes in controllers, models, components, migrations, commands, views, and selected web entrypoints are medium by default unless they are config-sensitive.
- Runtime, vendor, generated assets, tests, and static web asset paths should usually be excluded in YAML because they are noisy and not primary source-of-truth code.

Laravel file severity rules:

- `.env` and Laravel config files for app/auth/cache/database/filesystems/horizon/logging/mail/permission/queue/services/session/telescope are high risk because they can change credentials, authentication, storage, background workers, or observability exposure.
- PHP/PHAR/PHTML in writable public/storage/cache-style paths is high risk.
- Source changes in `app`, `routes`, `database/migrations`, `database/seeders`, `resources`, and selected public entrypoints are medium by default unless they are config-sensitive.
- Vendor, node_modules, storage, bootstrap/cache, generated public build/vendor assets, and tests should usually be excluded in YAML.

For each watched file it records:

```text
absolute path
relative path under site root when possible
size_bytes
mod_time
sha256 when hashed
hash_skipped when the file is too large to hash
```

It saves local state in:

```text
<state_dir>/sites/<site_slug>/file-watch.json
```

Then it diffs current state against previous state and queues:

- `file.created`
- `file.modified`
- `file.deleted`
- `file.scan.completed` when nothing changed

The agent does not send file contents. A file change event contains metadata and hashes, for example:

```json
{
  "path": "...",
  "relative_path": "modules/example/example.php",
  "size_bytes": 1234,
  "mod_time": "2026-05-15T00:00:00Z",
  "sha256": "one-way-file-content-hash",
  "previous_sha256": "previous-one-way-hash"
}
```

## Log Collector

For each configured `sites[].logs[]` path, the agent tails only new bytes since the previous scan. Existing old log lines are treated as baseline on the first scan; `--bootstrap` captures offsets without queueing log events.

Supported structured parsing:

- nginx/apache-style combined access logs.
- PHP-FPM, Apache/PHP, and application PHP error logs.
- Generic log lines when no structured parser matches.

Access log events are queued as `log.access` and contain:

```text
event time parsed from the log line
remote_addr
method
path
query_redacted
request_target_redacted
protocol
status_code
response_bytes when present
referer_redacted when present
user_agent with secrets redacted
line_sha256
```

If `remote_addr` is currently present in the Tor exit list, the agent adds:

```text
remote_is_tor = true
remote_network = tor_exit
remote_tags includes tor_exit
remote_addr_sha256
tor_exit_list_source
tor_exit_list_checked_at
tor_exit_list_size
```

Tor metadata is validation evidence. It does not block log collection. If the list cannot be fetched, the agent uses the cached list when available; otherwise it queues the access log event without Tor fields. The default list source is Tor Project's bulk exit list and the cache TTL is `6h`.

Tor-related environment controls:

```text
AEGRAIL_TOR_CHECK=0                  disable Tor checking
AEGRAIL_DISABLE_TOR_CHECK=1          disable Tor checking
AEGRAIL_TOR_EXIT_LIST_URL=<url>      override the exit list URL
AEGRAIL_TOR_EXIT_LIST_CACHE=<path>   override the local cache file
AEGRAIL_TOR_EXIT_LIST_TTL=6h         override cache freshness
```

Admin/login and account-recovery paths are intentionally retained because they explain account activity:

- WordPress: `/wp-login.php` login POSTs and reset actions such as `action=lostpassword`, `retrievepassword`, and `resetpass`.
- PrestaShop: admin-login request hints such as `controller=AdminLogin`, `submitLogin`, and admin-login targets.
- Mautic: `/s/...`, `/login`, `/passwordreset`, `/password/reset`, OAuth/API/admin paths, and server errors.
- Yii2 RBAC: login/logout, admin/user/profile/RBAC/debug/Gii paths, plus `request-password-reset`, `reset-password`, and related user/site password-reset routes.
- Laravel: login/logout, admin/dashboard/API/profile/users/roles/permissions/reports/import/shortener/Horizon/Telescope paths, plus `forgot-password`, `password/email`, `password/reset`, and `reset-password`.

The access log can prove that a login or reset request was made. It cannot always prove the application accepted the credentials, because some frameworks return `200` for both success and failure. Hub reports redirect-style login POSTs as likely success; repeated non-redirect login attempts are handled by the existing burst rules.

Mautic access-log filtering:

- Routine email/campaign tracking traffic below `500` is dropped for paths such as `/r/...`, `/email/...`, `/mtracking.gif`, `/mtc/event`, `/mtc.js`, `/asset/...`, `/download/...`, `/page/...`, and `/form/submit...`.
- Static assets are dropped for status codes below `500`, including noisy `404` CSS/image/font requests.
- Admin, API, OAuth, installer, upgrade, login/logout, password-reset, direct PHP probes, and server errors are kept.
- The goal is to avoid turning email redirect volume into dashboard noise while still preserving request evidence that can validate compromise or operational errors.

Yii2 RBAC access-log filtering:

- Static assets under `/assets/`, `/app-assets/`, `/css/`, `/js/`, `/favicon/`, and common image/font/map suffixes are dropped below `500`.
- `GET /`, `GET /robots.txt`, and `GET /favicon.ico` below `400` are dropped.
- Login/logout, admin, user/profile, RBAC, password-reset, Yii debug/Gii, direct PHP probes, and server errors are kept.

Laravel access-log filtering:

- Static assets, Vite/build assets, public vendor assets, favicons, and common image/font/map suffixes are dropped below `500`.
- `GET /`, `GET /robots.txt`, and favicon requests below `400` are dropped.
- Login/logout, admin/dashboard/API/profile/users/roles/permissions/reports/import/shortener/Horizon/Telescope paths, password-reset paths, direct PHP probes, and server errors are kept.

PHP error events are queued as `log.php_error` and contain:

```text
event time when parseable
level
message_redacted
source_log_redacted
remote_addr when present
file and line_number when present
```

## WordPress Database Collector

The agent reads the DSN from `sites[].databases[].dsn_env`. It does not accept literal DSNs in config validation.

For WordPress and WordPress multisite, the default table prefix is `wp_` unless `table_prefix` is configured. The prefix is sanitized to letters, numbers, and underscore before being used in SQL identifiers.

Every database run collects count and digest checks:

```sql
SELECT COUNT(*) FROM {prefix}users;
SELECT COUNT(DISTINCT user_id)
FROM {prefix}usermeta
WHERE meta_key REGEXP '^<prefix>([0-9]+_)?capabilities$'
  AND meta_value LIKE '%administrator%';
SELECT COUNT(*) FROM {prefix}options;
SELECT option_value FROM {prefix}options WHERE option_name = 'active_plugins' LIMIT 1;
SELECT option_value FROM {prefix}options WHERE option_name = 'cron' LIMIT 1;
SELECT option_value FROM {prefix}options WHERE option_name = 'stylesheet' LIMIT 1;
SELECT option_value FROM {prefix}options WHERE option_name = 'template' LIMIT 1;
```

For `option_value` rows, the raw value is not sent. The agent sends:

```text
option_name
value_sha256 = SHA256(option_value)
value_bytes
status
signature
```

User entities are collected with:

```sql
SELECT
  u.ID,
  COALESCE(u.user_login, ''),
  COALESCE(u.user_email, ''),
  COALESCE(GROUP_CONCAT(COALESCE(um.meta_value, '') ORDER BY um.meta_key SEPARATOR '\n'), '')
FROM {prefix}users u
LEFT JOIN {prefix}usermeta um
  ON um.user_id = u.ID
 AND um.meta_key REGEXP '^<prefix>([0-9]+_)?capabilities$'
GROUP BY u.ID, u.user_login, u.user_email
ORDER BY u.ID
LIMIT 1000;
```

For each user the agent builds a `wordpress_user` entity:

```text
user_id_hash = SHA256(user ID)
capabilities_sha256 = SHA256(raw capabilities blob)
administrator = true when capabilities contain "administrator"
network_super_admin = true when multisite site_admins contains the login
email = normalized full email when present
login = normalized full login when present
email_masked/login_masked = display hint
email_hmac_sha256/login_hmac_sha256 = HMAC-SHA256(AEGRAIL_PII_KEY, identifier) when configured
signature = SHA256(entity type + label + privileged flag + sorted attributes)
```

Important: SHA-256 and HMAC-SHA256 are one-way fingerprints. The Hub does not decode them. Full email/login is included today for account findings because otherwise the dashboard cannot tell you which account changed.

The collector also reads selected WordPress options and multisite options:

```sql
SELECT option_name, COALESCE(option_value, '')
FROM {prefix}options
WHERE option_name IN (...)
ORDER BY option_name
LIMIT 100;

SELECT meta_key, COALESCE(meta_value, '')
FROM {prefix}sitemeta
WHERE meta_key IN (...)
ORDER BY meta_key
LIMIT 100;
```

Those are transformed into entities such as:

- `wordpress_option`
- `wordpress_plugin`
- `wordpress_theme`
- `wordpress_cron_hook`
- `wordpress_network_option`
- `wordpress_content_script`

Raw option/content values are not sent for those entities; values become hashes, byte counts, parsed plugin/theme names, cron hook names, script indicators, and signatures.

WordPress content-script checks scan posts, selected builder postmeta, and widget options for script-like patterns such as:

```text
<script
<iframe
javascript:
onerror=
onload=
document.write
eval(
atob(
```

Those observations store content SHA-256, byte count, indicator names, external domains, hashed post/meta identifiers, and signatures. They do not store raw post content.

## PrestaShop Database Collector

For PrestaShop, the default table prefix is `ps_` unless `table_prefix` is configured.

Every database run collects count checks:

```sql
SELECT COUNT(*) FROM {prefix}employee;
SELECT COUNT(*) FROM {prefix}employee WHERE active = 1;
SELECT COUNT(*) FROM {prefix}module;
SELECT COUNT(*) FROM {prefix}module WHERE active = 1;
SELECT COUNT(*) FROM {prefix}configuration;
SELECT COUNT(*) FROM {prefix}hook;
SELECT COUNT(*) FROM {prefix}tab;
SELECT COUNT(*) FROM {prefix}access;
```

Employee entities are collected with:

```sql
SELECT id_employee, COALESCE(email, ''), active, id_profile
FROM {prefix}employee
ORDER BY id_employee
LIMIT 1000;
```

For each employee the agent builds a `prestashop_employee` entity:

```text
employee_id_hash = SHA256(id_employee)
profile_id
active
super_admin = true when id_profile is 1
email = normalized full email when present
email_masked = display hint
email_hmac_sha256 = HMAC-SHA256(AEGRAIL_PII_KEY, email) when configured
signature = SHA256(entity type + label + privileged flag + sorted attributes)
```

Module entities are collected with:

```sql
SELECT id_module, COALESCE(name, ''), active, COALESCE(version, '')
FROM {prefix}module
ORDER BY id_module
LIMIT 2000;
```

Configuration entities are collected with:

```sql
SELECT name, COALESCE(value, '')
FROM {prefix}configuration
WHERE name IN (...) OR name LIKE ? OR ...
ORDER BY name
LIMIT 1000;
```

Raw PrestaShop configuration values are not sent. For tracked keys and patterns the agent sends:

```text
config_name
category
value_sha256 = SHA256(value)
value_bytes
empty
sensitive
suspicious
suspicious_reason
value_bool when parseable
signature
```

## Mautic Database Collector

For Mautic, the default table prefix is empty unless `table_prefix` is configured.

Every database run collects count checks:

```sql
SELECT COUNT(*) FROM {prefix}users;
SELECT COUNT(*) FROM {prefix}users WHERE is_published = 1;
SELECT COUNT(*) FROM {prefix}roles;
SELECT COUNT(*) FROM {prefix}roles WHERE is_admin = 1;
SELECT COUNT(*) FROM {prefix}plugins;
SELECT COUNT(*) FROM {prefix}plugins WHERE is_missing = 1;
SELECT COUNT(*) FROM {prefix}plugin_integration_settings WHERE is_published = 1;
SELECT COUNT(*) FROM {prefix}oauth2_clients;
SELECT COUNT(*) FROM {prefix}webhooks;
```

User entities are collected from `users` and joined to `roles` when the roles table exists:

```sql
SELECT
  u.id,
  COALESCE(u.username, ''),
  COALESCE(u.email, ''),
  COALESCE(u.role_id, 0),
  COALESCE(r.name, ''),
  COALESCE(CAST(r.is_admin AS SIGNED), 0),
  COALESCE(CAST(u.is_published AS SIGNED), 0),
  u.date_added,
  u.date_modified
FROM {prefix}users u
LEFT JOIN {prefix}roles r ON r.id = u.role_id
ORDER BY u.id
LIMIT 1000;
```

For each user the agent builds a `mautic_user` entity:

```text
user_id_hash = SHA256(user ID)
role_id_hash = SHA256(role ID)
role_name
admin_role = true when joined role is_admin is true
published = true when is_published is true
email = normalized full email when present
login = normalized full username when present
email_masked/login_masked = display hint
email_hmac_sha256/login_hmac_sha256 = HMAC-SHA256(AEGRAIL_PII_KEY, identifier) when configured
signature = SHA256(entity type + label + privileged flag + source timestamps + sorted attributes)
```

Role entities are collected from `roles` and include role name, admin flag, permissions SHA-256, permissions byte size, timestamps when present, and a signature. Raw readable-permissions content is not sent.

Plugin entities are collected from `plugins` and include name, bundle, version, missing state, timestamps when present, and a signature.

Integration entities are collected from `plugin_integration_settings`. Raw `api_keys`, `supported_features`, and `feature_settings` values are not sent. The agent emits SHA-256 digests, byte sizes, published state, and whether API keys are present. A published integration with API keys is privileged evidence.

OAuth client entities are collected from `oauth2_clients`. Raw OAuth secrets, random IDs, redirects, and grant-type blobs are not sent. The agent emits SHA-256 digests, byte sizes, secret-present state, role ID hash, timestamps when present, and a signature. OAuth clients are treated as privileged evidence.

Webhook entities are collected from `webhooks`. Raw webhook URLs and secrets are not sent. The agent emits URL host, URL SHA-256, secret-present state, secret SHA-256, byte size, published state, timestamps when present, and a signature.

## Yii2 RBAC Database Collector

The `yii2-rbac` profile supports PostgreSQL and MySQL/MariaDB. It targets RBAC-enabled Yii2 applications with the common `users`, role, migration, and optional Yii RBAC table shapes.

Every database run checks the tables that exist:

```sql
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM users WHERE status = 10;
SELECT COUNT(*) FROM roles;
SELECT COUNT(*) FROM roles WHERE LOWER(role) IN (...) OR LOWER(role) LIKE '%admin%';
SELECT COUNT(*) FROM auth_assignment;
SELECT COUNT(*) FROM auth_assignment WHERE LOWER(item_name) IN (...) OR LOWER(item_name) LIKE '%admin%';
SELECT COUNT(*) FROM auth_item WHERE type = 1;
SELECT COUNT(*) FROM auth_item WHERE type = 2;
SELECT COUNT(*) FROM migration;
```

The collector adapts to missing optional tables. `users` and `roles` are the primary layout. `auth_assignment` and `auth_item` are collected when Yii RBAC tables exist.

User entities are collected from `users`, with role assignment context from `roles`:

```sql
SELECT id, username when present, email when present, status when present, created_at, updated_at
FROM users
ORDER BY id
LIMIT 1000;
```

For each user the agent builds a `yii2_rbac_user` entity:

```text
user_id_hash = SHA256(user ID)
status and active=true when status is 10
roles, role_count, roles_sha256
admin_role = true when a role looks admin-like
email/login = normalized full values when present
email_masked/login_masked = display hint
email_hmac_sha256/login_hmac_sha256 = HMAC-SHA256(AEGRAIL_PII_KEY, identifier) when configured
source_created_at/source_updated_at from Unix timestamp columns when present
signature = SHA256(entity type + label + privileged flag + source timestamps + sorted attributes)
```

Role/RBAC entities are collected as `yii2_rbac_role_assignment`, `yii2_rbac_item`, and `yii2_rbac_assignment`. Raw password hashes, auth keys, activation keys, and reset tokens are never selected or sent.

## Laravel Database Collector

The `laravel` profile supports MySQL/MariaDB and PostgreSQL for the monitored Laravel layout. It targets standard Laravel users plus Spatie permission tables when present.

Snapshot checks include user counts, active/verified users when those columns exist, Spatie roles/permissions, role and permission assignments, migrations, password reset tokens, sessions, failed jobs, and activity log rows.

Entity observations:

- `laravel_user`: id hash, normalized email/name for identifying the account, masked compatibility fields, optional HMAC fingerprints when `AEGRAIL_PII_KEY` is set, active/email verification state, last-login timestamp, last-login IP hash, role count, role hash, and admin-role flag. The agent never selects `password`, `remember_token`, reset tokens, or session payloads.
- `laravel_role`: role name, guard, admin-like flag, created/updated source timestamps.
- `laravel_permission`: permission name, guard, access scope, sensitive flag, created/updated source timestamps.
- `laravel_role_assignment`: user-id hash, role-id hash, role name, model type, admin-role flag.
- `laravel_role_permission`: role-id hash, permission-id hash, role/permission names, privileged flag.
- `laravel_permission_assignment`: user-id hash, permission-id hash, permission name, model type, privileged flag.

## Database State And Events

After a database snapshot, the agent prepares the next local state:

```text
<state_dir>/sites/<site_slug>/db-<database_name>.json
```

Then it compares the new snapshot to the previous one. On normal runs, that new
state is committed only after the related queue batch is written successfully.
If queueing fails or the process crashes first, the next run repeats the diff
instead of silently accepting an unreported state.

First run behavior:

- Normal first run creates a local baseline and queues `db.snapshot.baseline_created`.
- `--bootstrap` creates the baseline but queues no detection events.

Subsequent runs queue events like:

- `db.snapshot.completed`
- `db.snapshot.check`
- `db.coverage.warning`
- `db.snapshot.check_added`
- `db.snapshot.check_changed`
- `db.snapshot.check_removed`
- `db.entity.added`
- `db.entity.changed`
- `db.entity.removed`

If a WordPress admin user is added, the event path is:

```text
SELECT users/usermeta
-> build wordpress_user entity
-> compare entity signature against db state JSON
-> queue db.entity.added
-> Hub stores event
-> rules create or refresh a finding
-> dashboard shows the issue with the account email/login from the event attributes
```

## Browser Collector

For each configured URL, the browser collector crawls same-host pages up to `max_pages`, using rendered or non-rendered mode depending on config.

Crawler identity:

- The default primary User-Agent is `AegrailBot/0.1 (+https://aegrail.local/monitoring; Aegrail bot)`.
- The page evidence records which User-Agent was used.
- If the named bot is blocked or fails with a bot-filter style response (`403`, `406`, or `429`), the collector retries with a short browser-like fallback list based on current reduced User-Agent strings, including Chrome 148 and Firefox 150 as of May 2026.
- You can override the primary header with `browser_crawl.user_agent` and the fallback list with `browser_crawl.fallback_user_agents`.
- Fallbacks are compatibility helpers. They do not bypass authentication, forms, paywalls, or private areas; the collector only visits URLs that you configured.

For each page it queues `browser.crawl.completed` with:

```text
page_url
final_url
mode
user_agent
status_code
title
canonical_url
site_icons
script_count
warning_count
run_started_at/run_finished_at
```

For each script it queues `browser.script.observed` with:

```text
page_url
final_url
user_agent
source_type
url
url_redacted
domain
path
sha256 for inline script content
inline_bytes
response_status
content_type
attributes
tag_manager / tag_manager_ids
initial_html / dynamically_loaded
```

Browser URL privacy:

- `page_url`, `final_url`, `canonical_url`, script `url`, and script `url_redacted` are redacted before they enter the queue.
- Query values with names like `token`, `session`, `password`, `secret`, `api_key`, and `access_token` are replaced with `[REDACTED]`.
- Script attributes such as `src` are also redacted before sending.
- The agent still emits `domain`, `path`, inline `sha256`, byte size, response status, content type, and tag-manager IDs so the Hub can detect drift without storing private query material.

For tag managers it also queues `browser.tag_manager.detected`. Crawl failures/timeouts/status problems become `browser.coverage.warning`.

## Queue Files And Wire Protocol

Events are grouped into local batch JSON files in:

```text
<queue_dir>/pending
<queue_dir>/sent
<queue_dir>/failed
<queue_dir>/discarded
```

`pending` is the retry spool. After the Hub accepts a batch, the Agent deletes
the local JSON by default. `sent` is only used when
`runtime.sent_retention` is set to a positive duration such as `1h` for
transport debugging. Do not use sent retention on production nodes unless you
intentionally want a short local audit cache.

Queue and state files are written defensively. The Agent writes JSON state to a
temporary file in the same directory, flushes it, renames it into place, and
best-effort flushes the parent directory. Pending queue batches and browser
schedule markers are also flushed before they are eligible to be sent or used
for skip decisions. This keeps crash or power-loss failures from silently
producing half-written state or disappearing pending batches.

A queued batch has this shape:

```json
{
  "schema": "aegrail.agent.queue.v1",
  "queued_at": "2026-05-15T00:00:00Z",
  "org": "company-slug",
  "project": "project-slug",
  "environment": "local",
  "app": "site-slug",
  "service": "frontend",
  "host": "node-slug",
  "agent_id": "agt_site_local",
  "batch_id": "unique-agent-batch-id",
  "source": "agent.database",
  "region": "local",
  "labels": {},
  "events": []
}
```

When sending with `hub.protocol: aegrail-wire-v1`, the Agent encrypts the queued JSON body and posts a wire envelope to:

```text
POST <hub.url>/api/v1/ingest/events
```

Envelope:

```json
{
  "schema": "aegrail.agent.wire.v1",
  "node_id": "agt_site_local",
  "timestamp": "2026-05-15T00:00:00Z",
  "nonce": "base64url",
  "ciphertext": "base64url"
}
```

Wire v1 uses:

- X25519 between the node secret and Hub public key
- a scoped HMAC-SHA256 KDF for the shared secret
- AES-256-GCM for the JSON payload
- schema, node ID, and timestamp as authenticated associated data
- Hub timestamp skew checks to reject stale/replayed envelopes

Raw JSON ingest is not supported. The Hub stores the node public key and fingerprint, not the node secret. If a node is missing its Hub public key or node secret, the Agent leaves batches queued and reports a send error.

## Hub Ingest And PostgreSQL

Hub receives `/api/v1/ingest/events`, limits the body to `2 MiB`, and for wire v1 verifies:

```text
schema is aegrail.agent.wire.v1
node ID exists in Hub inventory
node public key exists
timestamp exists
timestamp is inside the accepted skew window
AES-GCM ciphertext decrypts successfully
decrypted JSON decodes successfully
inventory path exists: org -> project -> environment -> host -> agent
```

Then Hub builds normalized ingest events, hashes the normalized event body, and stores:

- `hub_ingest_batches`: external batch ID, org/project/environment/app/service/host/agent IDs, source, body SHA-256, request signature, accepted status, event count, received time, metadata.
- `hub_ingest_events`: batch ID, org/project/environment/app/service/host/agent IDs, event time, received time, event type, target, severity, message, region, labels JSON, payload JSON.

Deduplication is by `(agent_id, external_id)`. If the same batch is retried, Hub returns the existing stored batch instead of duplicating events.

After a new batch is stored, Hub auto-correlates interesting events into findings. Findings keep dedupe keys and event IDs so repeated scans refresh the same issue instead of creating endless duplicates.

The dashboard reads Hub APIs. It does not decode hashes or run hidden collectors.

## Baseline Workflow

The first baseline run should not create issue noise:

```powershell
cd agent
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml --once --bootstrap
```

If old local test batches are pending and should not be sent:

```powershell
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml --once --bootstrap --discard-pending
```

Then run without `--bootstrap` for normal monitoring.

## Detection And Findings

Current rule families:

- Database snapshot and entity changes for WordPress, PrestaShop, Mautic, Yii2 RBAC, and Laravel.
- Suspicious file path changes, including PHP under writable paths and sensitive config changes.
- Grouped plugin, theme, and module file changes so a new extension does not create a wall of separate issues.
- Browser script drift, including new domains, URLs, inline hashes, and tag manager IDs.
- Web/admin request anomalies from normalized logs, including single admin login POST observations and password-reset request observations.
- Multi-host file baseline drift.
- Correlated incident chains such as web activity followed by file and database changes.

Finding metadata should be operator-friendly:

- Database user issues should show the full account identifier when available, plus masked/HMAC hints for matching and display.
- File issues should group related files and show a capped changed-file list.
- Risk metadata records severity, confidence, rule category, event count, host count, deployment context, score, and band.
- Deployment windows can lower expected low/medium drift but must not hide high-risk administrator, payment, persistence, or incident-chain findings.

Rule evaluation:

```powershell
cd hub
go run ./cmd/hub rules evaluate --fail-on-mismatch
```

## Agent Configuration

The config schema is `aegrail.agent.server_config.v1`.

Reduced example:

```yaml
schema: aegrail.agent.server_config.v1

hub:
  url: http://127.0.0.1:8787
  protocol: aegrail-wire-v1
  hub_public_key: paste-hub-public-key
  node_secret_env: AEGRAIL_NODE_SECRET

identity:
  org: acme
  project: customer-sites
  environment: production
  host: web-01
  agent_id: agt_web_01

runtime:
  queue_dir: C:\aegrail\queue
  state_dir: C:\aegrail\state
  interval: 30s

sites:
  - slug: example-wordpress
    domain: example.test
    app: example-wordpress
    service: frontend
    kind: wordpress
    root: C:\sites\example-wordpress
    files:
      profiles: [wordpress]
    databases:
      - name: wordpress
        engine: mysql
        profile: wordpress
        table_prefix: wp_
        dsn_env: AEGRAIL_DB_EXAMPLE_WORDPRESS_DSN
        schedule: 5m
    browser_crawl:
      enabled: true
      rendered: true
      urls:
        - https://example.test/
```

Validation and run commands:

```powershell
cd agent
go run ./cmd/agent config validate --config configs/agent.multi-site.example.yaml
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml --once
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml
```

For a commented reference containing every supported agent YAML option, see `agent/configs/agent.full.example.yaml`.

Notes:

- WordPress profiles include `wp-config.php`, `wp-config-local.php`, uploads, plugins, and themes.
- PrestaShop profiles include config, modules, themes, upload/img/media-like paths, and logs where configured.
- Mautic profiles include `.env`, app/config, config, media, plugins, and themes. Runtime cache/log/session/spool/temp directories are ignored.
- Yii2 RBAC profiles include source/config/migration directories plus selected web entrypoints. Exclude vendor, runtime, generated assets, and tests unless there is a specific reason to monitor them.
- Laravel profiles include source/config/routes/migrations/resources plus selected public entrypoints. Exclude vendor, node_modules, storage, bootstrap/cache, generated public build/vendor assets, and tests unless there is a specific reason to monitor them.
- Database `schedule` controls how often a database snapshot runs; file/browser/config checks can run more frequently.
- Provider-managed nodes can disable unavailable local collectors with `files.enabled: false` and can mark config coverage as intentionally disabled with `coverage.enabled: false`.
- Config coverage emits a periodic heartbeat, even when unchanged, so dashboards can distinguish stale data from an intentionally quiet site.
- Missing DSN environment variables should produce coverage warnings rather than stopping unrelated site scans.

## Ignoring File Noise

There are two layers:

- Hub ignore rule: created from the dashboard. It suppresses future Hub findings for matching file path prefixes and marks the current issue false positive. It does not require an agent restart.
- Agent `files.exclude`: configured in YAML. It stops scanning and sending those paths entirely. The continuous agent reloads YAML between scan loops, so a process restart is usually not required; wait for the next loop after editing the config. If the agent is run as a one-shot command, run it again.

Agent-side file ignores are also reported in the config coverage payload so an admin can see what each node is configured to skip. The agent does not send local roots. It reports:

- site-relative ignore paths such as `modules/custom/logs`
- `<site root>` when the whole site root is excluded
- `[outside site root]/name` for excludes outside the site root
- a simple risk hint: `low`, `medium`, or `high`

Example agent-side exclude:

```yaml
sites:
  - slug: example-prestashop
    files:
      exclude:
        - /var/www/example/modules/custommodule/logs
```

Use Hub ignore rules for fast triage from the dashboard. Add `files.exclude` later when the path is known to be permanently noisy and safe to stop collecting.

If you add `files.exclude` to an existing agent state without a Hub ignore rule, the next scan can interpret the removed state entries as deleted files. To avoid that one-time noise, create the Hub ignore first or refresh the agent baseline with `--bootstrap` after changing excludes.
