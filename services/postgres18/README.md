# PostgreSQL 18

This service provides the local Aegrail development database.

It uses the pinned pgvector PostgreSQL 18 image so the `vector` extension is available without a custom Docker build. Core PostgreSQL extensions used by Aegrail are enabled by `initdb/001_extensions.sql`.

Default local settings:

```text
host: localhost
port: 55432
database: aegrail
user: aegrail
password: aegrail
```

The defaults are intentionally simple for local development only.

The Docker volume is mounted at `/var/lib/postgresql` because PostgreSQL 18 images store data in a major-version-specific subdirectory.
