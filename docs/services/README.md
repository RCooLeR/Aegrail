# Services

`services/` contains local infrastructure for development and testing.

Current services:

- PostgreSQL 18 with pgvector support, used by the Hub.
- Redis, optional for tiny tests but recommended for normal multi-site Hub queue and lock work.

Docs:

- [Install](install.md)
- [Docker Examples](../../docker/examples/README.md)

Code:

```text
services/compose.yaml
services/postgres18/initdb/001_extensions.sql
docker/examples/
```
