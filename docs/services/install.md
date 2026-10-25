# Services Install

## Start Local Services

Copy and edit the environment template first:

```powershell
Copy-Item docker\services\.env.example docker\services\.env
```

Set strong local-only values for `AEGRAIL_POSTGRES_PASSWORD` and
`AEGRAIL_REDIS_PASSWORD`. The compose file refuses to start without them.

```powershell
docker compose --env-file docker/services/.env -f docker/services/compose.yaml up -d postgres18 redis
```

Local PostgreSQL connection string shape:

```text
postgres://aegrail:<url-encoded-password>@localhost:55432/aegrail?sslmode=disable
```

Local settings from `.env`:

```text
host: localhost
port: 55432
database: aegrail
user: aegrail
password: AEGRAIL_POSTGRES_PASSWORD
```

Local Redis URL shape:

```text
redis://:<redis-password>@localhost:56379/0
```

PostgreSQL and Redis bind to `127.0.0.1` by default. Hub uses Redis for
short-lived work queues and locks when it is configured. Agents never connect
to Redis; keep the Redis port private to the machine or service network running
Hub.

The Compose service enables required PostgreSQL extensions from:

```text
docker/services/postgres18/initdb/001_extensions.sql
```

Hub migrations use PostgreSQL 18's native `uuidv7()` function for new
database-generated identifiers. Existing identifiers are not rewritten.

## Stop

```powershell
docker compose --env-file docker/services/.env -f docker/services/compose.yaml down
```

## Reset Local Services

This deletes the local database and Redis volumes:

```powershell
docker compose --env-file docker/services/.env -f docker/services/compose.yaml down -v
```

This service is for local development only. Do not place real customer data in committed service configs.
