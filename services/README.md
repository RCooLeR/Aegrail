# Aegrail Services

Local development infrastructure lives here.

Start PostgreSQL 18 with pgvector:

```powershell
docker compose -f services/compose.yaml up -d postgres18
```

Default local connection string:

```text
postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable
```

Stop services:

```powershell
docker compose -f services/compose.yaml down
```

Remove the local database volume:

```powershell
docker compose -f services/compose.yaml down -v
```

This service is for local development only. Do not place real customer data in committed service configs.
