# Hub Install

## Prerequisites

- Go matching the version in `hub/go.mod`.
- PostgreSQL with the migrations in `hub/migrations`.
- A Hub wire private key for encrypted Agent traffic.
- A strong user secret for encrypting pending and active TOTP secrets.

For local PostgreSQL, see [Services Install](../services/install.md).

## Environment

Start from the example:

```powershell
cd hub
Copy-Item configs\hub.env.example .env.local
```

Set the equivalent environment values in your shell/service manager:

```powershell
$env:AEGRAIL_DATABASE_URL = "postgres://aegrail:replace-with-url-encoded-password@localhost:55432/aegrail?sslmode=disable"
$env:AEGRAIL_REDIS_URL = "redis://:replace-with-redis-password@localhost:56379/0"
$env:AEGRAIL_REDIS_KEY_PREFIX = "aegrail"
$env:AEGRAIL_CORRELATION_WORKERS = "1"
$env:AEGRAIL_HUB_USER_SECRET = "replace-with-strong-user-secret"
```

`go run ./cmd/hub serve` validates that `AEGRAIL_DATABASE_URL`,
`AEGRAIL_HUB_USER_SECRET`, and `AEGRAIL_HUB_WIRE_PRIVATE_KEY` are set. Local
development can use generated throwaway values, but do not reuse local secrets
for real projects.

Redis is optional for very small local tests. For the normal 20+ site setup, configure it. Hub uses Redis for short-lived ingest correlation jobs, distributed worker locks, and shared auth rate limiting, while PostgreSQL still stores durable evidence, findings, users, sessions, and reports.

On small NAS hardware, keep `AEGRAIL_CORRELATION_WORKERS=1`. Increase it only
after the Hub stays comfortably below CPU limits during agent backlog replay.

Built-in retention worker:

```text
AEGRAIL_MAINTENANCE_INTERVAL=1h
AEGRAIL_RETENTION_EVENTS=180d
AEGRAIL_RETENTION_RESOLVED_FINDINGS=0
AEGRAIL_RETENTION_MODEL_REPORTS=180d
AEGRAIL_RETENTION_AUTH_EVENTS=180d
AEGRAIL_RETENTION_BATCH_SIZE=5000
AEGRAIL_DB_SOFT_LIMIT_BYTES=0
```

The worker runs inside `hub serve` on startup and then at the interval. It
prunes old ingest events not linked to open/acknowledged findings, empty old
ingest batches, old model-analysis reports not linked to active findings, and
old authentication audit events. Resolved/false-positive findings are kept by
default (`AEGRAIL_RETENTION_RESOLVED_FINDINGS=0`) so operator history remains
available; if explicitly enabled, finding deletion has a 30-day minimum guard
and only removes findings whose created, updated, and last-event timestamps are
all older than the cutoff. High and Critical findings are never deleted by this
automatic cleanup path. The default window is six months (`180d`) for events,
model reports, and auth audit events.
Durations support Go syntax such as `4320h` and day syntax such as `180d`.
Set `AEGRAIL_MAINTENANCE_INTERVAL=0` to disable the worker temporarily.
Owners can inspect database size and core table estimates through
`GET /api/v1/system/status`.

Dashboard authentication lockout:

- Ten failed password/TOTP attempts for an existing user lock that user for 15 minutes.
- A correct password during the lockout window is still rejected.
- Successful login resets the failed counter.
- Login success/failure, TOTP failure, lockout, and logout events are stored in `hub_auth_events`.

CLI audit lookup:

```powershell
go run ./cmd/hub users auth-events --email operator@example.test --since 24h --limit 100
```

Temporary ingest troubleshooting:

```text
AEGRAIL_INGEST_DEBUG=true
```

When enabled, Hub logs every Agent ingest stage: `received`, `decoded`,
`parsed`, `accepted`, or the failure stage such as `decode_failed`,
`signature_mismatch`, or `save_failed`. The logs include scope IDs, batch ID,
event counts, and errors, but not decrypted event payloads or secrets. Turn it
off after debugging because busy Agents can produce many lines.

Optional notification base URL:

```text
AEGRAIL_HUB_PUBLIC_URL
```

Set this to the operator-facing Hub URL, for example
`https://aegrail.example.test`. Email and browser-push notifications use it to
link back to issue details.

Optional finding notification webhook:

```text
AEGRAIL_NOTIFICATION_WEBHOOK_URL
AEGRAIL_NOTIFICATION_WEBHOOK_SECRET
AEGRAIL_NOTIFICATION_WEBHOOK_TIMEOUT
```

When configured, Hub sends JSON when findings are observed and when an operator changes finding status. If `AEGRAIL_NOTIFICATION_WEBHOOK_SECRET` is set, each request includes `X-Aegrail-Signature: sha256=<hmac>`.

Optional SMTP email notifications:

```text
AEGRAIL_NOTIFICATION_EMAIL_SMTP_HOST=smtp.example.test
AEGRAIL_NOTIFICATION_EMAIL_SMTP_PORT=587
AEGRAIL_NOTIFICATION_EMAIL_USERNAME=<smtp-username>
AEGRAIL_NOTIFICATION_EMAIL_PASSWORD=<smtp-password>
AEGRAIL_NOTIFICATION_EMAIL_FROM=Aegrail <alerts@example.test>
AEGRAIL_NOTIFICATION_EMAIL_TO=ops@example.test,security@example.test
AEGRAIL_NOTIFICATION_EMAIL_MIN_SEVERITY=high
AEGRAIL_NOTIFICATION_EMAIL_EVENTS=finding.observed,finding.status_updated
AEGRAIL_NOTIFICATION_EMAIL_TIMEOUT=10s
```

Email sends HTML summaries over SMTP with STARTTLS when the server supports it.
With the default `high` threshold, newly persisted High/Critical findings send
mail immediately from the Hub save path. Credentials are read from environment
only and are not stored in PostgreSQL.

Optional browser push notifications:

```powershell
cd hub
go run ./cmd/hub notifications vapid-keys
```

Then set:

```text
AEGRAIL_NOTIFICATION_PUSH_VAPID_PUBLIC_KEY=<generated-public-key>
AEGRAIL_NOTIFICATION_PUSH_VAPID_PRIVATE_KEY=<generated-private-key>
AEGRAIL_NOTIFICATION_PUSH_SUBJECT=security@example.test
AEGRAIL_NOTIFICATION_PUSH_MIN_SEVERITY=medium
AEGRAIL_NOTIFICATION_PUSH_EVENTS=finding.observed
AEGRAIL_NOTIFICATION_PUSH_TTL=3600
AEGRAIL_NOTIFICATION_PUSH_TIMEOUT=10s
```

Dashboard users opt in from Settings -> Profile. Browser push requires HTTPS or
localhost, an active Hub session, and the user's browser notification
permission. The Hub stores push endpoint/key material in PostgreSQL and disables
subscriptions that return `404` or `410`.

New-finding notification intent is durable: Hub commits one PostgreSQL outbox
row per configured transport with the finding, attempts delivery immediately,
and retries transport failures in the background without failing correlation
workers. Apply the current Hub migrations before restarting so the notification
outbox table exists. Browser push uses public push providers such as FCM over
TLS, so Docker images must
include a current CA bundle. The example Hub image copies Debian's
`ca-certificates.crt` and sets `SSL_CERT_FILE`. If browser push TLS fails with
`x509: certificate signed by unknown authority`, rebuild the Hub image from the
current Dockerfile or install/mount a CA bundle into the running image. To
temporarily disable browser push, clear both
`AEGRAIL_NOTIFICATION_PUSH_VAPID_PUBLIC_KEY` and
`AEGRAIL_NOTIFICATION_PUSH_VAPID_PRIVATE_KEY`; email and webhook delivery remain
independent. Repeated provider failures are rate-limited in Hub logs so one bad
push provider cannot drown out collector errors.

Optional reverse-proxy trust:

```text
AEGRAIL_TRUSTED_PROXY_CIDRS
```

Hub parses trusted proxy CIDRs at startup and refuses to serve when any entry is invalid. It trusts `X-Forwarded-Proto` and `X-Forwarded-Host` only from loopback or from CIDRs listed in `AEGRAIL_TRUSTED_PROXY_CIDRS`, for example `10.0.0.0/8,172.16.0.0/12`. Leave it empty when Hub is not behind a trusted reverse proxy.

Generate and set the Hub wire key for encrypted Agent traffic:

```powershell
go run ./cmd/hub wire keygen
$env:AEGRAIL_HUB_WIRE_PRIVATE_KEY = "paste-generated-private-key"
```

The matching public key is shown in node sample configs. Re-provision nodes before rotating this key.

Optional model-analysis values:

```text
AEGRAIL_OLLAMA_BASE_URL
AEGRAIL_OLLAMA_INVESTIGATION_MODEL
AEGRAIL_OLLAMA_INVESTIGATION_MODELS
AEGRAIL_OLLAMA_EMBEDDING_MODEL
AEGRAIL_OLLAMA_TIMEOUT
AEGRAIL_MODEL_ANALYSIS_AUTO
AEGRAIL_MODEL_ANALYSIS_INTERVAL
AEGRAIL_MODEL_ANALYSIS_LIMIT
```

Recommended local investigation model order:

| Rank | Model | Ollama ref | Best use |
| --- | --- | --- | --- |
| 1 | Qwen2.5-Coder-14B-Instruct | `qwen2.5-coder:14b` | Best overall for source-code website security review. |
| 2 | Mistral Small 3.2 24B Instruct | `mistral-small3.2:latest` | Better general reasoning, reports, and structured output. |
| 3 | DeepSeek-Coder-V2-Lite-Instruct | `deepseek-coder-v2:16b` | Good coding alternative, efficient for local use. |
| 4 | Qwen3-14B | `qwen3:14b` | Good general reasoning, less specifically code-security tuned. |
| 5 | StarCoder2-15B | `starcoder2:15b` | Good code model, older and less instruction/security-review friendly. |

Set `AEGRAIL_OLLAMA_INVESTIGATION_MODELS` to the comma-separated order above. If `AEGRAIL_OLLAMA_INVESTIGATION_MODEL` is empty, Hub selects the first installed model from the ranked list. Use `AEGRAIL_OLLAMA_TIMEOUT=5m` or higher for larger local models.

## Database

```powershell
cd hub
go run ./cmd/hub db migrate
go run ./cmd/hub db status
```

The project is still pre-production, so new installs use the initial schema plus
small upgrade migrations for local development databases that already ran an
older schema. For a clean production test, start with an empty database and run
all migrations in order. Migration runs serialize through a renewable
PostgreSQL `goose_lock` lease, so concurrent deploy jobs cannot apply the same
migration at once and another job can recover the lock after a crashed runner.

`hub serve` checks the database migration version before accepting traffic. If
the database is behind the binary, start fails with a clear error so Agents do
not queue against a half-upgraded Hub. Run `hub db migrate`, then start Hub
again. `AEGRAIL_ALLOW_PENDING_MIGRATIONS=true` exists only as an emergency
troubleshooting escape hatch.

For single-instance Docker/NAS installs where running a separate migration
command is awkward, set:

```text
AEGRAIL_MIGRATE_ON_START=true
```

With that enabled, `hub serve` applies bundled migrations first, then performs
the same schema currency check before accepting traffic. The renewable migration
lease serializes replicas that start together; a dedicated migration job is
still preferable for clustered rollouts so application startup does not wait on
schema work.

Hub also validates typed environment variables at startup. Invalid booleans,
integers, and durations are reported by name instead of silently falling back to
defaults.

## Run

Serve the API only:

```powershell
go run ./cmd/hub serve
```

Serve the API and built dashboard:

```powershell
go run ./cmd/hub serve --dashboard-dir ..\dashboard\dist
```

Container health probe:

```powershell
go run ./cmd/hub healthcheck
```

The healthcheck command verifies required config, database connectivity,
configured Redis connectivity, and migration currency. Ollama/model-analysis is
optional health, so an Ollama outage reports degraded health but does not make
the Hub container unhealthy for ingest/dashboard purposes.

When Redis is configured, `serve` starts correlation workers automatically.
Every security-relevant ingest batch still runs an immediate correlation pass;
Redis is a fallback/catch-up queue and is not required for prompt
notifications. Agents still send HTTPS/HTTP requests to the Hub API or your
reverse proxy; they never connect to Redis.

Default local API address is:

```text
http://127.0.0.1:8787
```

## Docker Example

Example Hub image and Compose files live in
[`docker/examples`](../../docker/examples/README.md). The example builds the
dashboard, copies Hub migrations into the image, runs PostgreSQL/Redis, and
keeps real secrets in an ignored `.env.hub` file.

Basic flow:

```powershell
Copy-Item docker\examples\.env.hub.example docker\examples\.env.hub
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml build hub
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml run --rm --no-deps hub wire keygen
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml run --rm hub-migrate
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml up -d hub
```

Replace every placeholder secret before starting Hub against real projects.
Use HTTPS or a trusted private reverse proxy for non-local Agent traffic.

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/healthz
```

`/healthz` returns `200` when required dependencies are healthy and `503` when
PostgreSQL or configured Redis is unavailable. Ollama/model-analysis failures
are reported as degraded health because the Hub can still ingest evidence and
serve the dashboard while local model infrastructure is being repaired. Ollama
`offline` mode is also reported but is not treated as unhealthy.

## Verification

```powershell
cd hub
go test ./...
go run ./cmd/hub --help
```

PostgreSQL adapter integration tests are opt-in because they need a disposable database:

```powershell
$env:AEGRAIL_TEST_POSTGRES_URL = "postgres://user:pass@localhost:5432/aegrail_test?sslmode=disable"
go test ./internal/adapters/postgres
```

The integration tests create and drop their own temporary schema.
