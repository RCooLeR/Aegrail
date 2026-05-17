# Services Install

## Start Local Services

```powershell
docker compose -f services/compose.yaml up -d postgres18 redis
```

Default local connection string:

```text
postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable
```

Default local settings:

```text
host: localhost
port: 55432
database: aegrail
user: aegrail
password: aegrail
```

Default Redis URL:

```text
redis://localhost:56379/0
```

Hub uses Redis for short-lived work queues and locks when it is configured. Agents never connect to Redis; keep the Redis port private to the machine or service network running Hub.

The Compose service enables required PostgreSQL extensions from:

```text
services/postgres18/initdb/001_extensions.sql
```

## Stop

```powershell
docker compose -f services/compose.yaml down
```

## Reset Local Services

This deletes the local database and Redis volumes:

```powershell
docker compose -f services/compose.yaml down -v
```

This service is for local development only. Do not place real customer data in committed service configs.
