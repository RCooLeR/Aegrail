# Pantheon WordPress Monitoring Plan

Status: planned
Date: 2026-05-12

Canonical context:

- [Architecture](../02_ARCHITECTURE.md)
- [Evidence Collection](../04_EVIDENCE_COLLECTION.md)
- [Delivery Plan](../08_DELIVERY_PLAN.md)

## Goal

Aegrail should support Pantheon-hosted WordPress sites as a first-class deployment target. This includes both single WordPress installations and Pantheon WordPress Multisite networks.

Minimum useful monitoring:

- access and application logs
- database snapshots or read-only database checks
- WordPress-specific users, roles, options, plugins, themes, cron, and Multisite network state
- Hub labels that preserve Pantheon site, environment, container, and network context

## Pantheon Shape To Design Around

Pantheon environments are explicit operating boundaries: Dev, Test, Live, and Multidev. Aegrail should model each Pantheon environment as an Aegrail environment, with optional labels for the Pantheon site UUID, environment name, workspace, framework, upstream, and region.

Pantheon log files are per environment and can be retrieved through SFTP. Application logs live on application containers, while database logs live on database containers. Multi-application-container environments require collection from every relevant appserver, not just one container.

Pantheon nginx access logs are valuable but not a complete traffic source. Requests served entirely by Pantheon's CDN may not reach nginx and therefore may not appear in `nginx-access.log`. Aegrail should treat nginx logs as application-server evidence and leave room for CDN/Fastly logs later.

Pantheon WordPress Multisite uses a distinct `wordpress_network` framework. A Multisite network shares one codebase and one database, but has many logical sites. Aegrail should represent the network as the monitored app and each network site as a logical WordPress site under that app.

## Access Log Collection

Initial collector path:

```text
Pantheon SFTP / appserver logs
  -> download or tail environment logs
  -> parse nginx-access.log, php-error.log, php-slow.log, php-fpm-error.log
  -> normalize into Hub events
  -> label by org/project/environment/app/service/host/container
```

Required labels:

- `platform=pantheon`
- `pantheon_site_id`
- `pantheon_env`
- `pantheon_container_type=appserver`
- `pantheon_container_id` when discoverable
- `wordpress_mode=single` or `wordpress_mode=network`
- `network_site_id` and `network_domain` when a Multisite request can be resolved

Important behaviors:

- collect all relevant appserver logs for an environment
- record UTC timestamps as event time
- preserve source log filename and byte/window metadata
- tolerate rotated and gzipped logs
- avoid assuming nginx logs are complete traffic history
- mark evidence gaps when logs are missing, destroyed during appserver migration, or only partially collected

## Database Monitoring

Minimum viable DB approach:

```text
Pantheon connection info or Terminus
  -> MySQL read-only query or database backup download
  -> WordPress snapshot builder
  -> deterministic diff and findings
```

Preferred implementation order:

1. Backup-based import for safe offline snapshots.
2. Read-only MySQL collector using current Pantheon connection info.
3. Optional SSH/TLS tunnel support where needed by customer policy.

Single WordPress snapshot tables:

- `wp_users`
- `wp_usermeta`
- `wp_options`
- plugin/theme state from options and filesystem evidence
- cron option

WordPress Multisite snapshot tables:

- global users and usermeta
- `wp_site`
- `wp_blogs`
- `wp_sitemeta`
- per-site options tables such as `wp_2_options`
- per-site users/capabilities mappings
- network-active plugins and site-active plugins

Pantheon database connection details can change over time, so Aegrail should not store long-lived plaintext credentials. It should support refreshing connection info through Terminus or user-supplied connection metadata, and it should redact credentials from logs and reports.

## Findings To Prioritize

Single WordPress:

- new administrator account
- changed administrator capabilities
- changed `siteurl`, `home`, `active_plugins`, `template`, `stylesheet`, `cron`, or suspicious autoloaded options
- new or changed plugins/themes
- PHP file in writable uploads paths

WordPress Multisite:

- new Super Admin
- changed network admin capabilities
- new or changed network-active plugin
- suspicious `siteurl` or `home` change on any network site
- unexpected new network site
- network site mapped to suspicious domain
- cross-site plugin/theme drift that should be network-managed

Pantheon-specific:

- environment connection target changed unexpectedly
- appserver log coverage is incomplete
- DB snapshot is stale compared with log timeline
- Live environment shows admin/DB changes outside a deployment or maintenance window

## Open Design Questions

- Should Pantheon collection be a dedicated `collector pantheon` command or a provider mode under generic SFTP/MySQL collectors?
- Should Aegrail call Terminus directly, read exported Terminus JSON, or support both?
- How should we store Pantheon site UUID and environment metadata in inventory without making the core inventory Pantheon-specific?
- What is the best first path for CDN/Fastly logs when customers need complete edge request history?

## Source Notes

- [Pantheon environment logs](https://docs.pantheon.io/guides/logs-pantheon) are available through SFTP, scoped per environment, timestamped in UTC, and subject to platform retention/container lifecycle limits.
- [Pantheon access logs](https://docs.pantheon.io/guides/logs-pantheon/nginx-access-logs) are useful appserver evidence, but CDN-served requests may not appear in `nginx-access.log`.
- [Pantheon log SFTP access](https://docs.pantheon.io/guides/logs-pantheon/access-logs) covers both appserver logs and database-server logs.
- [Pantheon WordPress Multisite](https://docs.pantheon.io/guides/multisite) uses the `wordpress_network` framework with one shared codebase and database.
- [Pantheon MySQL connection information](https://docs.pantheon.io/guides/mariadb-mysql/mysql-access) is environment-specific and can change.
- [Terminus connection info](https://docs.pantheon.io/terminus/commands/connection-info) can provide SFTP and MySQL fields in machine-readable formats.
- [Terminus backup listing](https://docs.pantheon.io/terminus/commands/backup-list) supports database backup discovery for safer offline snapshot workflows.
