# Agent Tracker

## Done

- Separate `agent/` Go module with its own `go.mod`, configs, command, and internal packages.
- Multi-site YAML config loading and validation.
- Bootstrap mode for first safe baseline.
- Local queue/state handling and Hub replay.
- Atomic/synced state writes and flushed pending queue batches before send eligibility.
- Encrypted Hub replay through `aegrail.agent.wire.v1`.
- File monitoring with path metadata, size, mtime, SHA-256, delete detection, and reusable hashes for unchanged files.
- Log tailing for access logs, PHP errors, generic logs, and Tor exit metadata when enabled.
- WordPress, WordPress multisite, PrestaShop, Mautic, Yii2 RBAC, and Laravel database snapshots.
- Mautic file profile, DB snapshots, DB entity diffs, and access-log noise filtering.
- Yii2 RBAC file profile, PostgreSQL/MySQL DB snapshots, users/roles/RBAC entity diffs, and static-asset access-log filtering.
- Laravel file profile, MySQL/PostgreSQL DB snapshots, users/roles/permissions entity diffs, and static-asset access-log filtering.
- Account evidence with full normalized email/login plus optional HMAC fingerprints.
- Browser crawl observations for script URLs, domains, inline hashes, tag-manager IDs, and favicon candidates.
- Named browser crawler identity (`AegrailBot/0.1 ... Aegrail bot`) with browser-like fallback User-Agents for compatibility-only retries.
- Browser crawl payloads redact page URLs, final URLs, canonical URLs, script URLs, and script attributes before queue/send.
- Config coverage events with safe collector state and sanitized ignore paths.
- PrestaShop module, WordPress plugin/theme, and Mautic plugin/integration profile logic.
- Default file-ignore tuning for cache variants, generated frontend assets, module/plugin logs, dependency install folders, and known app runtime directories.
- Per-site collector status summaries for files, logs, databases, browser crawls, and config coverage.
- File-event framework/deploy evidence for WordPress, PrestaShop, Mautic, Yii2 RBAC, Laravel, writable PHP, dependency manifests, routes, migrations, views, and source areas.

## Next

- Validate the new noise filters and crawler User-Agent behavior against the local test sites and add any project-specific ignores through Agent config rather than code defaults.

## Later

- Provider-managed collectors where filesystem access is not available.
- Per-agent secrets or mTLS.
- More CMS/framework profiles.
