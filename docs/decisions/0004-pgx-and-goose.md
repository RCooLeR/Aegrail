# ADR 0004: Use Pgx And Goose For PostgreSQL

Date: 2026-05-12
Status: accepted

## Context

Aegrail needs PostgreSQL-first persistence, explicit migrations, and a database layer that can support direct PostgreSQL features such as JSONB, arrays, `inet`, `citext`, trigram indexes, and vectors.

## Decision

Use `github.com/jackc/pgx/v5` with `pgxpool` for application database access.

Use `github.com/pressly/goose/v3` for SQL migrations.

## Consequences

- Repositories can use PostgreSQL-native types and efficient connection pooling.
- Migration files stay plain SQL under `app/migrations`.
- Goose uses `database/sql`, so the migration adapter registers the pgx stdlib driver for migration execution.
- CLI commands can expose `aegrail db migrate` and `aegrail db status` without requiring a separate migration binary.
