# PostgreSQL 18 Service

Local PostgreSQL 18 with pgvector for Aegrail development.

Default local settings:

```text
host: localhost
port: 55432
database: aegrail
user: aegrail
password: aegrail
```

The Compose service uses a pgvector PostgreSQL image and enables Aegrail's required extensions from `initdb/001_extensions.sql`.

This is local development infrastructure only. Production or pilot deployments should use separate credentials, backups, network controls, and retention rules.
