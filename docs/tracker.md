# Project Tracker

## Done

- Split `aegrail-hub` and `aegrail-agent` binaries, with `aegrail` kept as compatibility CLI.
- Removed legacy local evidence/site/workspace code from the active app.
- PostgreSQL storage and local Docker service.
- Signed Hub ingest.
- Distributed inventory: organizations, projects, environments, apps, services, hosts, agents.
- Multi-site agent config loading, validation, file scans, log tailing, database checks, browser crawls, queueing, replay, and coverage reporting.
- WordPress and PrestaShop database snapshots with redacted entity diffs.
- WordPress Multisite network option support.
- `wp-config-local.php` included in WordPress file coverage.
- Browser script observations and allowlist workflow.
- Deterministic rule registry, risk scoring, deployment context, and fixture evaluation.
- Finding lifecycle actions.
- Dashboard refactor into modular React app.
- Dashboard overview/company/site/node/issues/signals/browser/deployments/report/settings views.
- Browser scripts page with allowlist review and revoke/reinstate actions.
- Deployment marker page with timeframe preview and confirmation.
- Tabbed settings for profile, Hub scope, triage defaults, companies, sites, nodes, users/2FA, and inventory.
- Dashboard auth users, access levels, and pending TOTP verification before 2FA activation.
- Grouped file findings for plugin/theme/module changes.
- Full account display in database user/employee findings when evidence contains it.
- Dashboard-created Hub ignore rules for noisy file directories.
- Safe agent config coverage in node details, including sanitized ignore paths.

## Next

- Polish dashboard issue resolution flow so each warning clearly says why it exists and what action is expected.
- Add tighter rule coverage for expected cache/upload churn and allowed CMS-generated paths.
- Add report views that make deterministic reports and model reports easier to compare.
- Improve operational setup scripts for local Hub plus multiple agents.
- Add notification hooks after the issue model is stable.

## Later

- Remote collectors for provider-managed sites.
- Pantheon and other hosting adapters.
- Scheduled Hub-side jobs.
- Per-agent secrets or mTLS.
- Audit log and retention settings.
- More CMS/framework profiles beyond WordPress and PrestaShop.
