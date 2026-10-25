# Backup And Restore Runbook

This runbook covers the self-hosted Aegrail Hub database. Redis is not part of
the durable backup set; it only holds short-lived queues, locks, and rate-limit
state.

## What To Back Up

Back up PostgreSQL. It contains:

- companies, sites, environments, nodes, and agents
- ingest events and batches
- findings, comments, status history, deployments, allowlists, and ignore rules
- dashboard users, sessions, TOTP ciphertext, and authentication audit events
- notification subscriptions and model-analysis reports

Also back up deployment configuration outside Git:

- Hub environment file
- reverse-proxy config
- Docker compose files used on the host
- Agent YAML/env files, especially node secrets

Do not put those runtime configs into the repository.

## Suggested Retention

Aegrail keeps Hub data for six months by default:

```text
AEGRAIL_RETENTION_EVENTS=180d
AEGRAIL_RETENTION_RESOLVED_FINDINGS=0
AEGRAIL_RETENTION_MODEL_REPORTS=180d
AEGRAIL_RETENTION_AUTH_EVENTS=180d
```

That keeps triaged finding history in PostgreSQL while pruning older raw events,
model reports, and auth audit events after six months. Keep backup retention
longer than Hub data retention when you need older forensic history.

## Manual Backup

Run from a machine that can reach PostgreSQL:

```bash
export AEGRAIL_DATABASE_URL='postgres://aegrail:replace-with-url-encoded-password@127.0.0.1:55432/aegrail?sslmode=disable'
mkdir -p backups
pg_dump "$AEGRAIL_DATABASE_URL" --format=custom --file "backups/aegrail-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

For Docker-hosted PostgreSQL:

```bash
docker exec aegrail-postgres18 pg_dump -U aegrail -d aegrail --format=custom > "aegrail-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Store backup files somewhere outside the Docker volume host. A backup on the
same disk as the database protects against mistakes, not disk loss.

## Restore Drill

Do this against a scratch database, not production.

1. Create an empty scratch database.

```bash
createdb aegrail_restore_test
```

2. Restore the dump.

```bash
pg_restore --dbname aegrail_restore_test --clean --if-exists backups/aegrail-YYYYMMDDTHHMMSSZ.dump
```

3. Point a temporary Hub process at the restored database.

```bash
export AEGRAIL_DATABASE_URL='postgres://aegrail:replace-with-url-encoded-password@127.0.0.1:55432/aegrail_restore_test?sslmode=disable'
export AEGRAIL_HUB_WIRE_PRIVATE_KEY='replace-with-restore-test-wire-key'
export AEGRAIL_HUB_USER_SECRET='replace-with-restore-test-user-secret'
go run ./cmd/hub db status
```

4. Verify that core counts look plausible.

```sql
SELECT count(*) FROM organizations;
SELECT count(*) FROM hub_findings;
SELECT count(*) FROM hub_ingest_events;
SELECT count(*) FROM hub_users;
```

5. Record the drill date, dump file, and result in your private operations
notes.

## Production Restore

1. Stop Hub and Agents, or block Agent traffic at the reverse proxy.
2. Take one final pre-restore dump if the database is readable.
3. Restore into an empty database or a new PostgreSQL volume.
4. Run migrations with the same Hub build you plan to start:

```bash
hub db migrate
hub db status
```

5. Start Hub.
6. Start one Agent first and confirm new ingest appears.
7. Start the remaining Agents in small batches.

## Quick Checks After Restore

- `/healthz` reports PostgreSQL healthy.
- Dashboard login works.
- Overview and Settings load the expected company/site/node inventory.
- Recent findings and timeline rows are visible.
- One Agent sends a new batch successfully.
- Notification settings still point to the expected provider.
