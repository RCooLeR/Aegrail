# Hub Tracker

## Done

- Separate `hub/` Go module with its own `go.mod`, config example, command, migrations, and internal packages.
- Encrypted Agent wire ingest with node key lookup and timestamp validation.
- Encrypted `aegrail.agent.wire.v1` ingest envelopes with X25519/AES-GCM.
- Admin provisioning APIs for companies, sites, nodes, and generated Agent config samples.
- PostgreSQL storage for inventory, events, findings, users, reports, allowlists, deployments, and ignore rules.
- Redis-backed ingest correlation queue and distributed model-analysis worker lock.
- Deterministic rule registry, correlation, risk scoring, and fixture evaluation.
- Mautic database/entity correlation rules for users, roles, plugins, integrations, OAuth clients, and webhooks.
- Yii2 RBAC database/entity correlation rules for users, roles, RBAC assignments, and migrations.
- Laravel database/entity correlation rules for users, roles, permissions, sessions, reset tokens, and migrations.
- Finding lifecycle actions and baseline acceptance.
- Browser script allowlist workflows.
- File ignore rules created from dashboard findings.
- Deployment markers with expected rollout context.
- Users, access levels, sessions, and pending TOTP verification before activation.
- Model analysis queue and persisted prompt/evidence/report provenance.
- Dashboard static serving from built assets.
- Operator-action metadata on findings so warnings and alerts explain the concrete review action and final status choice.
- Finding review report that places deterministic Hub findings beside latest model analysis.
- Notification hooks for observed findings and finding status changes, with optional signed webhook delivery.

## Next

- Validate notification payloads against the eventual Slack/Teams/email adapter shape.

## Later

- More scheduled Hub jobs.
- Audit log and retention settings.
- Per-agent secrets or mTLS.
- Hosted/provider inventory adapters.
