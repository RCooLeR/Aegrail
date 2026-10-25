# Services

`docker/services/` contains local infrastructure for development and testing.

Current services:

- PostgreSQL 18 with pgvector 0.8.7, used by the Hub. New database-generated
  identifiers use PostgreSQL 18's time-ordered UUIDv7 defaults.
- Redis 8.10.2, optional for tiny tests but recommended for normal multi-site Hub
  queue and lock work.

Docs:

- [Install](install.md)
- [Backup And Restore Runbook](../runbooks/backup-restore.md)
- [Docker Examples](../../docker/examples/README.md)

Code:

```text
docker/services/compose.yaml
docker/services/postgres18/initdb/001_extensions.sql
docker/examples/
```

Redis 8 remains compatible with the RESP protocol used by Hub. Redis 8 is
tri-licensed under RSALv2, SSPLv1, or AGPLv3; review the upstream terms if you
redistribute Redis or offer it as a managed service.
