# ADR 0003: Use PostgreSQL 18 With Pgvector For Local Development

Date: 2026-05-12
Status: accepted

## Context

Aegrail needs PostgreSQL extensions for cryptographic IDs, fuzzy search, vector similarity, JSON-heavy event lookup, and case-insensitive text.

## Decision

Use a local Docker Compose service named `postgres18` with the pinned `pgvector/pgvector:0.8.2-pg18-trixie` image.

Mount the Docker volume at `/var/lib/postgresql`, not `/var/lib/postgresql/data`, because PostgreSQL 18 images use major-version-specific data directories under that path.

The init script enables:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS citext;
```

## Consequences

- Local development has vector support without maintaining a custom Postgres image.
- The service stays isolated under `services`.
- Production can still use managed PostgreSQL if the same extensions are available.
