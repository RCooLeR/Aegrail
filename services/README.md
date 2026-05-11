# Aegrail Services

Local infrastructure for development lives here.

## PostgreSQL 18

Start the database:

```powershell
docker compose -f services/compose.yaml up -d postgres18
```

Connection string:

```text
postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable
```

The service uses `pgvector/pgvector:0.8.2-pg18-trixie`, which is a PostgreSQL 18 image with pgvector installed. The init script enables:

- `pgcrypto`
- `pg_trgm`
- `vector`
- `btree_gin`
- `citext`

Stop the services:

```powershell
docker compose -f services/compose.yaml down
```

Remove local database volume:

```powershell
docker compose -f services/compose.yaml down -v
```

PostgreSQL 18 stores data in a major-version-specific directory under `/var/lib/postgresql`, so the Compose service mounts the volume at `/var/lib/postgresql` instead of `/var/lib/postgresql/data`.
