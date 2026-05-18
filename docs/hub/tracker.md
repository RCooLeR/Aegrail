# Hub Tracker

## Done

- Separate `hub/` Go module with its own `go.mod`, config example, command, migrations, and internal packages.
- Encrypted Agent wire ingest with node key lookup and timestamp validation.
- Encrypted `aegrail.agent.wire.v1` ingest envelopes with X25519/AES-GCM.
- Admin provisioning APIs for companies, sites, nodes, and generated Agent config samples.
- PostgreSQL storage for inventory, events, findings, users, reports, allowlists, deployments, and ignore rules.
- Redis-backed ingest correlation queue and distributed model-analysis worker lock.
- Dependency-aware `/healthz`, HTTP server timeouts, startup validation for Hub wire/user secrets, and bounded PostgreSQL pool defaults.
- Deterministic rule registry, correlation, risk scoring, and fixture evaluation.
- Mautic database/entity correlation rules for users, roles, plugins, integrations, OAuth clients, and webhooks.
- Yii2 RBAC database/entity correlation rules for users, roles, RBAC assignments, and migrations.
- Laravel database/entity correlation rules for users, roles, permissions, sessions, reset tokens, and migrations.
- Finding lifecycle actions and baseline acceptance.
- Browser script allowlist workflows.
- File ignore rules created from dashboard findings.
- Deployment markers with expected rollout context.
- Users, access levels, sessions, and pending TOTP verification before activation.
- TOTP replay protection and login/TOTP endpoint rate limiting.
- Model analysis queue and persisted prompt/evidence/report provenance.
- Finding-specific model-analysis report listing filtered in PostgreSQL.
- Dashboard static serving from built assets.
- Operator-action metadata on findings so warnings and alerts explain the concrete review action and final status choice.
- Finding review report that places deterministic Hub findings beside latest model analysis.
- Notification hooks for observed findings and finding status changes, with optional signed webhook delivery, Mailjet SMTP email, and browser push delivery.
- Graceful shutdown waits briefly for Hub background workers.

## Next

- Validate notification copy/noise levels during the first production site rollout.

## Later

- More scheduled Hub jobs.
- Audit log and retention settings.
- Per-agent secrets or mTLS.
- Hosted/provider inventory adapters.
