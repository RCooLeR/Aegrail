# Hub Tracker

## Done

- Separate `hub/` Go module with its own `go.mod`, config example, command, migrations, and internal packages.
- Encrypted Agent wire ingest with node key lookup and timestamp validation.
- Encrypted `aegrail.agent.wire.v1` ingest envelopes with X25519/AES-GCM.
- Admin provisioning APIs for companies, sites, nodes, and generated Agent config samples.
- PostgreSQL storage for inventory, events, findings, users, reports, allowlists, deployments, and ignore rules.
- Immediate ingest correlation with Redis fallback/catch-up queue and distributed model-analysis worker lock.
- Dependency-aware `/healthz`, HTTP server timeouts, startup validation for Hub wire/user secrets, and bounded PostgreSQL pool defaults.
- Deterministic rule registry, correlation, risk scoring, and fixture evaluation.
- Mautic database/entity correlation rules for users, roles, plugins, integrations, OAuth clients, and webhooks.
- Yii2 RBAC database/entity correlation rules for users, roles, RBAC assignments, and migrations.
- Laravel database/entity correlation rules for users, roles, permissions, sessions, reset tokens, and migrations.
- Static, React, and Node.js app kinds for inventory, node config generation, rule metadata, and model-analysis prompt context.
- Finding lifecycle actions and baseline acceptance.
- Browser script allowlist workflows.
- File ignore rules created from dashboard findings.
- Deployment markers with expected rollout context.
- Users, access levels, sessions, and pending TOTP verification before activation.
- TOTP replay protection and login/TOTP endpoint rate limiting.
- Login failure lockout and authentication audit events.
- Model analysis queue and persisted prompt/evidence/report provenance.
- Finding-specific model-analysis report listing filtered in PostgreSQL.
- Dashboard static serving from built assets.
- Operator-action metadata on findings so warnings and alerts explain the concrete review action and final status choice.
- Finding review report that places deterministic Hub findings beside latest model analysis.
- Notification hooks for observed findings and finding status changes, with optional signed webhook delivery, SMTP email, and browser push delivery.
- Graceful shutdown waits briefly for Hub background workers.
- Built-in retention pruning worker and owner-only system status endpoint.
- Six-month default retention policy for Hub events, resolved findings, model reports, and auth audit events.
- Baseline HTTP security headers on Hub API, dashboard assets, redirects, and 404 responses.
- Hub performance pass: bulk event inserts, batched finding saves, single-query ingest scope resolution, dedicated correlation timeline queries, coalesced immediate/fallback correlation jobs, low-signal log filtering, throttled session and agent heartbeat writes, cached push subscription reads, token-rotation suppression, and composite indexes for timeline, finding, model-report, and notification lookups.

## Next

- Validate notification copy/noise levels during the first production site rollout.
- Tune default retention windows after production data volume is known.

## Later

- Per-agent secrets or mTLS.
- Hosted/provider inventory adapters.
