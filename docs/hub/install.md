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
$env:AEGRAIL_DATABASE_URL = "postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable"
$env:AEGRAIL_REDIS_URL = "redis://localhost:56379/0"
$env:AEGRAIL_REDIS_KEY_PREFIX = "aegrail"
$env:AEGRAIL_CORRELATION_WORKERS = "2"
$env:AEGRAIL_HUB_USER_SECRET = "replace-with-strong-user-secret"
```

`go run ./cmd/hub serve` validates that `AEGRAIL_DATABASE_URL`,
`AEGRAIL_HUB_USER_SECRET`, and `AEGRAIL_HUB_WIRE_PRIVATE_KEY` are set. Local
development can use generated throwaway values, but do not reuse local secrets
for real projects.

Redis is optional for very small local tests. For the normal 20+ site setup, configure it. Hub uses Redis for short-lived ingest correlation jobs, distributed worker locks, and shared auth rate limiting, while PostgreSQL still stores durable evidence, findings, users, sessions, and reports.

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

Optional Mailjet SMTP email notifications:

```text
AEGRAIL_NOTIFICATION_EMAIL_SMTP_HOST=in-v3.mailjet.com
AEGRAIL_NOTIFICATION_EMAIL_SMTP_PORT=587
AEGRAIL_NOTIFICATION_EMAIL_USERNAME=<mailjet-api-key>
AEGRAIL_NOTIFICATION_EMAIL_PASSWORD=<mailjet-secret-key>
AEGRAIL_NOTIFICATION_EMAIL_FROM=Aegrail <alerts@example.test>
AEGRAIL_NOTIFICATION_EMAIL_TO=ops@example.test,security@example.test
AEGRAIL_NOTIFICATION_EMAIL_MIN_SEVERITY=medium
AEGRAIL_NOTIFICATION_EMAIL_EVENTS=finding.observed,finding.status_updated
AEGRAIL_NOTIFICATION_EMAIL_TIMEOUT=10s
```

Email sends HTML summaries over SMTP with STARTTLS when the server supports it.
Credentials are read from environment only and are not stored in PostgreSQL.

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
all migrations in order.

## Run

Serve the API only:

```powershell
go run ./cmd/hub serve
```

Serve the API and built dashboard:

```powershell
go run ./cmd/hub serve --dashboard-dir ..\dashboard\dist
```

When Redis is configured, `serve` starts correlation workers automatically. Agents still send HTTPS/HTTP requests to the Hub API or your reverse proxy; they never connect to Redis.

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
